# wantaekchoi.github.io

[English](README.md)

GitHub Actions가 렌더링하고 서명하는 신원·크리덴셜 엔드포인트.

| | |
|---|---|
| [`/.well-known/did.json`](https://wantaekchoi.github.io/.well-known/did.json) | `did:web:wantaekchoi.github.io` |
| [`/.well-known/security.txt`](https://wantaekchoi.github.io/.well-known/security.txt) | RFC 9116 |
| [`/.well-known/did-configuration.json`](https://wantaekchoi.github.io/.well-known/did-configuration.json) | DIF 도메인 연결 |
| [`/credentials/contributions.json`](https://wantaekchoi.github.io/credentials/contributions.json) | Open Badges 3.0 |
| [`/credentials/achievements/contributions.json`](https://wantaekchoi.github.io/credentials/achievements/contributions.json) | 배지가 수여하는 성취 정의 |

매 실행마다 다섯 개를 다시 만들고, 크리덴셜 두 개를 `eddsa-rdfc-2022`로 서명한 뒤
각각 검증기에 통과시킨다. 배지는 1EdTech의 `OB30Inspector`가, 도메인 연결은
`OB30Inspector`가 아예 거부하므로 같은 실행에서 렌더링된 DID 문서에 대고 확인한다.
통과하지 못한 것은 게시되지 않는다. 저장소에 되커밋하지도 않는다 — 엔드포인트는
러너와 배포된 사이트에만 존재한다.

## 직접 쓰려면

```bash
gh repo create <your-username>.github.io --template wantaekchoi/wantaekchoi.github.io --public --clone
cd <your-username>.github.io
./setup.sh
```

이름은 반드시 `<your-username>.github.io`여야 한다. `did:web`은 경로 없는 도메인을
`/.well-known/did.json`으로 해석하는데, 루트에서 서빙하는 건 사용자 사이트뿐이다.

포크하지 말고 템플릿에서 생성하라. 포크한 저장소는 사람이 직접 켜기 전까지
워크플로가 꺼져 있다.

`setup.sh`가 서명 키를 만들어 저장소 시크릿에 넣고, `config.json`을 채우고(만료일
둘 다 1년 뒤로), 백업 시트를 쓰고, Pages를 켜고, 첫 실행을 시작한다. 이미 키가 있는
저장소는 건드리지 않는다.

**백업 시트를 보관하라.** 시크릿은 GitHub에서 다시 꺼낼 수 없으므로 그 종이가 키의
유일한 사본이다. 같은 32바이트를 세 가지로 적어서 하나가 틀리면 나머지가 잡아낸다.
종이를 믿기 전에 `scripts/backup/verify_sheet.py`를 돌려라.

## 기여를 추가하려면

편집할 것이 없다. 매 실행마다 본인이 작성해 머지된 공개 PR을 전부 찾아 GitHub API로
다시 확인하고 증거로 싣는다. 하나를 빼려면 `badge.json`의 `exclude` 목록에
`owner/repo#123`을 넣으면 된다.

## 키를 교체하려면

새 키로 서명한 크리덴셜은 그 키를 알리는 문서가 실제로 서빙되기 전까지 검증되지
않는다. 그래서 교체는 두 번의 실행으로 나뉜다.

```bash
gh workflow run publish -f identity_only=true   # 새 키가 담긴 did.json 먼저 게시
gh workflow run publish                          # 그다음 그 키로 서명·검증
```

## 구성

```
config.json                 도메인, 사용자명, 키 ID, 만료일 둘
badge.json                  성취 문구와, 제외할 PR 참조
pipeline/                   엔드포인트와 크리덴셜 두 개를 렌더링
signer/                     eddsa-rdfc-2022으로 서명하고, 그 결과를 증명
contexts/                   해시로 고정된 JSON-LD 컨텍스트 — 서명은 네트워크를 타지 않는다
scripts/backup/             종이 백업: 생성, 검증, 복원
scripts/lint-workflows.py   고정되지 않은 액션과 깨진 블록 스칼라를 잡는다
.github/workflows/          위의 모든 일을 하는 워크플로 하나
```

주간 cron이 `config.json`의 만료일 둘을 감시하고, 하나라도 만료 30일 전이 되면
실패한다. 갱신은 파일을 고쳐 푸시하면 된다.
