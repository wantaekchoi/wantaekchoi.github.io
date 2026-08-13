import base64
import datetime
import json
import os
import subprocess
import unittest

from pipeline import keys
from pipeline import generate_did_document as gen_did
from pipeline import generate_domain_linkage as gen_dl
from pipeline import generate_security_txt as gen_sec
from pipeline import generate_humans_txt as gen_hum
from pipeline import bake_badge
from pipeline import validate_endpoints as validate

ED_ARGS = ["-algorithm", "ED25519"]


def ephemeral_pem_b64(algo_args):
    pem = subprocess.run(["openssl", "genpkey"] + algo_args,
                         capture_output=True, check=True).stdout
    return base64.b64encode(pem).decode()


_CONFIG = None


def test_config():
    global _CONFIG
    if _CONFIG is None:
        os.environ["TEST_ED_B64"] = ephemeral_pem_b64(ED_ARGS)
        _CONFIG = {
            "domain": "example.org",
            "github_username": "someone",
            "keys": {
                "ed25519": {"id": "gh-ed25519", "env": "TEST_ED_B64"},
            },
            # Deliberately in the past: no clock reading can produce these.
            "domain_linkage": {
                "valid_from": "2000-01-01T00:00:00Z",
                "valid_until": "2001-01-01T00:00:00Z",
            },
        }
    return _CONFIG


class KeysTest(unittest.TestCase):

    def test_ed25519_multibase_roundtrip(self):
        pem = base64.b64decode(ephemeral_pem_b64(ED_ARGS))
        mb = keys.ed25519_public_multibase(pem)
        self.assertTrue(mb.startswith("z6Mk"))
        raw = keys.b58decode(mb[1:])
        self.assertEqual(raw[:2], bytes.fromhex("ed01"))
        self.assertEqual(len(raw), 34)

    def test_b58_roundtrip_leading_zeros(self):
        data = b"\x00\x00\x01\x02"
        self.assertEqual(keys.b58decode(keys.b58encode(data)), data)

    def test_missing_env_exits(self):
        with self.assertRaises(SystemExit):
            keys.load_private_pem("NO_SUCH_ENV_VAR_12345")


class DidDocumentTest(unittest.TestCase):
    def test_structure(self):
        doc = gen_did.build(test_config())
        did = "did:web:example.org"
        self.assertEqual(doc["id"], did)
        self.assertEqual(doc["alsoKnownAs"], ["https://github.com/someone"])
        ids = [vm["id"] for vm in doc["verificationMethod"]]
        self.assertEqual(ids, [f"{did}#gh-ed25519"])
        (ed,) = doc["verificationMethod"]
        self.assertEqual(ed["type"], "Multikey")
        self.assertTrue(ed["publicKeyMultibase"].startswith("z6Mk"))
        self.assertEqual(doc["authentication"], [f"{did}#gh-ed25519"])
        self.assertEqual(doc["assertionMethod"], ids)
        for vm in doc["verificationMethod"]:
            self.assertEqual(vm["controller"], did)


class DomainLinkageTest(unittest.TestCase):
    def test_renders_byte_for_byte_twice(self):
        self.assertEqual(json.dumps(gen_dl.build(test_config()), indent=2),
                         json.dumps(gen_dl.build(test_config()), indent=2))

    def test_dates_come_from_config_not_the_clock(self):
        cred = gen_dl.build(test_config())
        linkage = test_config()["domain_linkage"]
        self.assertEqual(cred["validFrom"], linkage["valid_from"])
        self.assertEqual(cred["validUntil"], linkage["valid_until"])
        self.assertTrue(cred["validFrom"].startswith("2000-"))

    def test_both_date_vocabularies_agree(self):
        """DIF's MUSTs name issuanceDate/expirationDate; VC 2.0 renamed them.
        Writing only the DIF pair drops it from the signed graph, so both go in,
        and a verifier reading either one must see the same instant."""
        cred = gen_dl.build(test_config())
        self.assertEqual(cred["issuanceDate"], cred["validFrom"])
        self.assertEqual(cred["expirationDate"], cred["validUntil"])
        inline = [c for c in cred["@context"] if isinstance(c, dict)]
        self.assertEqual(len(inline), 1)
        self.assertEqual(set(inline[0]), {"issuanceDate", "expirationDate"})

    def test_subject_is_the_issuer(self):
        cred = gen_dl.build(test_config())
        did = "did:web:example.org"
        self.assertEqual(cred["issuer"], did)
        self.assertEqual(cred["credentialSubject"]["id"], did)
        self.assertEqual(cred["credentialSubject"]["origin"], "https://example.org")

    def test_resource_has_exactly_the_two_allowed_members(self):
        cred = gen_dl.build(test_config())
        self.assertNotIn("id", cred)             # DIF: id MUST NOT be present
        resource = gen_dl.wrap(cred)
        self.assertEqual(list(resource), ["@context", "linked_dids"])
        self.assertEqual(resource["linked_dids"], [cred])


class SecurityTxtTest(unittest.TestCase):
    def test_render(self):
        text = gen_sec.build({
            "contact": "https://github.com/someone",
            "expires": "2099-01-01T00:00:00Z",
            "preferred_languages": "ko, en",
            "canonical": "https://example.org/.well-known/security.txt",
        })
        lines = text.splitlines()
        self.assertEqual(lines[0], "Contact: https://github.com/someone")
        self.assertEqual(lines[1], "Expires: 2099-01-01T00:00:00Z")
        self.assertEqual(lines[2], "Preferred-Languages: ko, en")
        self.assertEqual(lines[3],
                         "Canonical: https://example.org/.well-known/security.txt")
        self.assertTrue(text.endswith("\n"))


class HumansTxtTest(unittest.TestCase):
    USER = {"login": "someone", "name": "Some One", "location": "Seoul"}
    DID = "did:web:example.org"

    def test_render(self):
        lines = gen_hum.build(self.USER, self.DID).splitlines()
        self.assertEqual(lines[0], "/* TEAM */")
        self.assertEqual(lines[2:], [
            "\tDeveloper: Some One",
            "\tGitHub: github.com/someone",
            "\tDID: did:web:example.org",
            "\tLocation: Seoul",
        ])

    def test_falls_back_to_login_and_drops_blank_location(self):
        text = gen_hum.build({"login": "someone", "name": None, "location": "  "},
                             self.DID)
        self.assertIn("\tDeveloper: someone", text)
        self.assertNotIn("Location", text)

    def test_renders_byte_for_byte_twice(self):
        self.assertEqual(gen_hum.build(self.USER, self.DID),
                         gen_hum.build(self.USER, self.DID))

    def test_validator_accepts_what_the_generator_wrote(self):
        text = gen_hum.build(self.USER, self.DID)
        self.assertEqual(validate.check_humans_txt(text, {"id": self.DID}), [])

    def test_did_drift_detected(self):
        text = gen_hum.build(self.USER, self.DID)
        errors = validate.check_humans_txt(text, {"id": "did:web:other.example"})
        self.assertEqual(len(errors), 1)
        self.assertIn("!=", errors[0])


def fake_credential():
    return {
        "id": "https://example.org/credentials/contributions.json",
        "issuer": {"name": "someone"},
        "credentialSubject": {"achievement": {"name": "Open Source Contributions"}},
    }


class BakeBadgeTest(unittest.TestCase):
    def setUp(self):
        self.cred = fake_credential()
        self.payload = json.dumps(self.cred, indent=2)

    def test_round_trip(self):
        svg = bake_badge.bake(self.cred, self.payload)
        self.assertEqual(bake_badge.extract(svg), self.payload)

    def test_output_is_well_formed_xml_with_the_ob_namespace(self):
        import xml.etree.ElementTree as ET
        root = ET.fromstring(bake_badge.bake(self.cred, self.payload))
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        self.assertEqual(list(root)[0].tag, bake_badge.CREDENTIAL_TAG)

    def test_renders_byte_for_byte_twice(self):
        self.assertEqual(bake_badge.bake(self.cred, self.payload),
                         bake_badge.bake(self.cred, self.payload))

    def test_cdata_terminator_refused(self):
        with self.assertRaises(ValueError):
            bake_badge.bake(self.cred, self.payload + "]]>")

    def test_markup_in_a_name_stays_text(self):
        """A profile name reaches the picture as text. It must not become markup,
        and the copy inside CDATA must survive unaltered."""
        import xml.etree.ElementTree as ET
        cred = fake_credential()
        cred["issuer"]["name"] = "</svg><script>x</script>"
        payload = json.dumps(cred)
        svg = bake_badge.bake(cred, payload)
        root = ET.fromstring(svg)
        self.assertEqual(root.findall(".//{http://www.w3.org/2000/svg}script"), [])
        texts = [e.text for e in root.findall("{http://www.w3.org/2000/svg}text")]
        self.assertIn("</svg><script>x</script>", texts)
        self.assertEqual(bake_badge.extract(svg), payload)

    def test_second_credential_tag_refused(self):
        svg = bake_badge.bake(self.cred, self.payload)
        doubled = svg.replace("<title>",
                              "<openbadges:credential>x</openbadges:credential>\n<title>")
        with self.assertRaises(ValueError):
            bake_badge.extract(doubled)

    def test_credential_must_be_the_first_child(self):
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:openbadges="{bake_badge.OB_NS}">'
               "<title>t</title>"
               "<openbadges:credential><![CDATA[{}]]></openbadges:credential></svg>")
        with self.assertRaises(ValueError):
            bake_badge.extract(svg)

    def test_short_text_keeps_its_preferred_size(self):
        self.assertEqual(bake_badge.fit("short", 24), 24)

    def test_long_names_shrink_to_stay_inside_the_image(self):
        name = "Open Source Contributions"
        size = bake_badge.fit(name, 36)
        self.assertLess(size, 36)
        self.assertLessEqual(len(name) * bake_badge.GLYPH_RATIO * size,
                             bake_badge.TEXT_BOX)

    def test_shrinking_stops_at_a_legible_size(self):
        """Past some length nothing both fits and can be read. Readable wins, and
        the text runs wide rather than becoming a grey smear."""
        self.assertEqual(bake_badge.fit("x" * 200, 36), 11)

    def test_validator_accepts_what_the_baker_wrote(self):
        svg = bake_badge.bake(self.cred, self.payload)
        self.assertEqual(validate.check_baked_badge(svg, self.payload), [])

    def test_validator_detects_a_swapped_payload(self):
        svg = bake_badge.bake(self.cred, self.payload)
        errors = validate.check_baked_badge(svg, self.payload.replace("someone", "else"))
        self.assertEqual(len(errors), 1)

    def test_validator_reports_malformed_svg_instead_of_raising(self):
        self.assertEqual(len(validate.check_baked_badge("<svg", self.payload)), 1)


class ValidateTest(unittest.TestCase):
    def test_valid_did_document_passes(self):
        self.assertEqual(validate.check_did_document(gen_did.build(test_config())), [])

    def test_corrupt_multibase_detected(self):
        doc = gen_did.build(test_config())
        doc["verificationMethod"][0]["publicKeyMultibase"] = "zQQQQ"
        self.assertTrue(any("Multikey" in e for e in validate.check_did_document(doc)))

    def test_dangling_reference_detected(self):
        doc = gen_did.build(test_config())
        doc["assertionMethod"].append("did:web:example.org#ghost")
        self.assertTrue(any("ghost" in e for e in validate.check_did_document(doc)))

    def test_expires_near_fails(self):
        soon = (datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        errors = validate.check_security_txt(f"Contact: x\nExpires: {soon}\n")
        self.assertTrue(any("renew" in e for e in errors))

    def test_expires_far_passes(self):
        errors = validate.check_security_txt(
            "Contact: x\nExpires: 2099-01-01T00:00:00Z\n")
        self.assertEqual(errors, [])

    def test_missing_contact_fails(self):
        errors = validate.check_security_txt("Expires: 2099-01-01T00:00:00Z\n")
        self.assertTrue(any("Contact" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
