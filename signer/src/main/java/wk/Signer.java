package wk;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.signer.DataIntegrityProofLdSigner;
import com.danubetech.dataintegrity.verifier.DataIntegrityProofLdVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItem;
import org.oneedtech.inspect.util.resource.FileResource;
import org.oneedtech.inspect.vc.OB30Inspector;

/**
 * Sign a credential with eddsa-rdfc-2022, then prove the result before it is written.
 * A credential that does not pass is never written, so the workflow cannot publish
 * something a validator rejects.
 *
 * Two proofs, because one validator does not cover both documents:
 *   Open Badges 3.0  -> the 1EdTech OB30Inspector.
 *   domain linkage   -> verify the fresh signature with the Danubetech verifier, keyed
 *                       from the DID document on disk. OB30Inspector is OB 3.0 only and
 *                       would reject a DomainLinkageCredential out of hand.
 *
 * Usage: signer &lt;unsigned.json&gt; &lt;signed.json&gt; &lt;verificationMethod&gt; &lt;created&gt; [did.json]
 * The optional 5th argument picks the domain-linkage path; without it nothing changes.
 * Reads the private key from DID_ED25519_PRIVATE_B64 (base64 of a PKCS#8 PEM).
 */
public final class Signer {

    public static void main(String[] args) throws Exception {
        if (args.length != 4 && args.length != 5) {
            System.err.println("usage: signer <unsigned.json> <signed.json> <verificationMethod> <created> [did.json]");
            System.err.println("       did.json present: verify the proof against that DID document instead of OB30Inspector");
            System.exit(2);
        }
        Path unsigned = Path.of(args[0]);
        Path signed = Path.of(args[1]);
        String verificationMethod = args[2];
        String created = args[3];

        Ed25519Bc.install();
        byte[] priv64 = privateKey64(System.getenv("DID_ED25519_PRIVATE_B64"));

        JsonLDObject jld = JsonLDObject.fromJson(Files.readString(unsigned));
        jld.setDocumentLoader(documentLoader());

        DataIntegrityProofLdSigner signer =
            new DataIntegrityProofLdSigner(new Ed25519_EdDSA_PrivateKeySigner(priv64));
        signer.setCryptosuite("eddsa-rdfc-2022");
        signer.setVerificationMethod(URI.create(verificationMethod));
        signer.setProofPurpose("assertionMethod");
        signer.setCreated(Date.from(Instant.parse(created)));
        signer.sign(jld);

        Path staging = Path.of(signed + ".candidate");
        Files.createDirectories(staging.toAbsolutePath().getParent());
        Files.writeString(staging, jld.toJson(true));

        if (args.length == 5) {
            verifyDomainLinkage(staging, Path.of(args[4]));
        } else {
            inspectOpenBadge(staging);
        }
        Files.move(staging, signed, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        System.out.println("valid, wrote " + signed);
    }

    /** The Open Badges 3.0 path: the official 1EdTech validator is the gate. */
    private static void inspectOpenBadge(Path staging) throws Exception {
        Report report = ((OB30Inspector) new OB30Inspector.Builder()
            .set(Behavior.TEST_INCLUDE_SUCCESS, true)
            .set(Behavior.VALIDATOR_FAIL_FAST, false)
            .build()).run(new FileResource(staging.toFile(),
                org.oneedtech.inspect.util.resource.ResourceType.VC_JSON_LD));

        for (ReportItem item : report.iterable(true)) {
            if (item.getOutcome() != Outcome.VALID) {
                System.out.println(item.getOutcome() + "  " + item.getTitle() + "  " + item.getMessage());
            }
        }
        System.out.println(report.getSummary());

        Outcome outcome = report.getSummary().getOutcome();
        if (outcome != Outcome.VALID) {
            Files.deleteIfExists(staging);
            System.err.println("OB30Inspector rejected the credential: " + outcome);
            System.exit(1);
        }
    }

    /**
     * The domain-linkage path. Verifies the signature just made, with the public key taken
     * from the DID document on disk -- resolving did:web would fetch the very document this
     * run is about to publish, and would put the network inside the gate.
     *
     * The Danubetech verifier never reads proof.verificationMethod: it checks the bytes
     * against whatever key it is handed. Binding the proof to a DID and that DID to the
     * document is therefore done here. A valid signature over the wrong document is wrong.
     */
    @SuppressWarnings("unchecked")
    private static void verifyDomainLinkage(Path staging, Path didDocument) throws Exception {
        try {
            JsonLDObject jld = JsonLDObject.fromJson(Files.readString(staging));
            jld.setDocumentLoader(documentLoader());
            Map<String, Object> credential = jld.getJsonObject();

            DataIntegrityProof proof = DataIntegrityProof.getFromJsonLDObject(jld);
            require(proof != null, "no Data Integrity proof in " + staging);
            String key = proof.getVerificationMethod().toString();

            String issuer = id(credential.get("issuer"));
            Map<String, Object> subject = (Map<String, Object>) credential.get("credentialSubject");
            require(issuer != null && issuer.startsWith("did:web:"), "issuer is not a did:web: " + issuer);
            require(issuer.equals(id(subject.get("id"))),
                "credentialSubject.id " + id(subject.get("id")) + " != issuer " + issuer);
            require(key.startsWith(issuer + "#"), "verificationMethod " + key + " is not a key of " + issuer);
            require(origin(issuer).equals(subject.get("origin")),
                "origin " + subject.get("origin") + " != " + origin(issuer));

            Map<String, Object> did = JsonLDObject.fromJson(Files.readString(didDocument)).getJsonObject();
            require(issuer.equals(did.get("id")), didDocument + " describes " + did.get("id") + ", not " + issuer);
            // DIF: verify "against key material referenced in the assertionMethod
            // section". A key merely listed in verificationMethod may be there for
            // authentication only, and signing assertions with it is not sanctioned.
            List<Object> assertion = (List<Object>) did.get("assertionMethod");
            require(assertion != null && assertion.stream().anyMatch(a -> key.equals(id(a))),
                key + " is not in the assertionMethod section of " + didDocument);
            Map<String, Object> method = ((List<Map<String, Object>>) did.get("verificationMethod")).stream()
                .filter(m -> key.equals(m.get("id"))).findFirst()
                .orElseThrow(() -> new IllegalStateException("key not in " + didDocument + ": " + key));

            byte[] multikey = Multibase.decode((String) method.get("publicKeyMultibase"));
            require(multikey.length == 34 && (multikey[0] & 0xff) == 0xed && (multikey[1] & 0xff) == 0x01,
                "not an Ed25519 Multikey: " + method.get("id"));

            require(new DataIntegrityProofLdVerifier(
                    new Ed25519_EdDSA_PublicKeyVerifier(Arrays.copyOfRange(multikey, 2, 34))).verify(jld),
                "signature does not verify under " + key);
            System.out.println("verified " + key + " against " + didDocument);
        } catch (Exception e) {
            Files.deleteIfExists(staging);
            System.err.println("domain linkage rejected: " + e);
            System.exit(1);
        }
    }

    private static void require(boolean ok, String message) {
        if (!ok) throw new IllegalStateException(message);
    }

    /** A node that is either "did:web:x" or {"id": "did:web:x"}. */
    @SuppressWarnings("unchecked")
    private static String id(Object node) {
        return node instanceof Map ? (String) ((Map<String, Object>) node).get("id") : (String) node;
    }

    /** did:web:host:a:b -&gt; https://host/a/b; %3A carries a port colon (did:web spec). */
    private static String origin(String did) {
        return "https://" + URLDecoder.decode(
            did.substring("did:web:".length()).replace(':', '/'), StandardCharsets.UTF_8);
    }

    /** base64(PKCS#8 PEM) -> libsodium layout: seed(32) || public(32). */
    private static byte[] privateKey64(String b64Pem) {
        if (b64Pem == null || b64Pem.isBlank()) {
            System.err.println("missing env: DID_ED25519_PRIVATE_B64");
            System.exit(2);
        }
        String pem = new String(Base64.getDecoder().decode(b64Pem.trim()));
        String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        byte[] seed = Arrays.copyOfRange(der, der.length - 32, der.length);
        byte[] pub = new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
        byte[] priv64 = new byte[64];
        System.arraycopy(seed, 0, priv64, 0, 32);
        System.arraycopy(pub, 0, priv64, 32, 32);
        return priv64;
    }

    /**
     * Contexts come off disk. Fetching them at signing time would make the proof depend
     * on someone else's uptime, and a changed context would silently change the
     * canonicalised bytes the signature covers.
     */
    private static ConfigurableDocumentLoader documentLoader() throws Exception {
        Path dir = Path.of("contexts");
        ConfigurableDocumentLoader loader = new ConfigurableDocumentLoader();
        loader.setEnableHttp(false);
        loader.setEnableHttps(false);
        java.util.Map<URI, com.apicatalog.jsonld.document.JsonDocument> local = new java.util.HashMap<>();
        for (String line : Files.readAllLines(dir.resolve("MAP"))) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] parts = line.split("\\s+", 2);
            try (var in = Files.newInputStream(dir.resolve(parts[1]))) {
                local.put(URI.create(parts[0]), com.apicatalog.jsonld.document.JsonDocument.of(in));
            }
        }
        loader.setLocalCache(local);
        loader.setEnableLocalCache(true);
        return loader;
    }
}
