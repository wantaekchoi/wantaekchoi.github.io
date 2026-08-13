# wantaekchoi.github.io

[English](README.md)

GitHub Actions가 렌더링하고 서명하는 신원·크리덴셜 엔드포인트.
무엇을 어디에 서빙하는지는 <https://wantaekchoi.github.io>.

검증을 통과하지 못한 것은 게시되지 않고, 저장소에 되커밋하지도 않는다 —
엔드포인트는 러너와 배포된 사이트에만 존재한다.

## 직접 쓰려면

```bash
gh repo create <your-username>.github.io --template wantaekchoi/wantaekchoi.github.io --public --clone
cd <your-username>.github.io
./setup.sh
```

이름은 반드시 `<your-username>.github.io`여야 한다. `did:web`은 경로 없는 도메인을
`/.well-known/did.json`으로 해석하는데, 루트에서 서빙하는 건 사용자 사이트뿐이다.
포크하지 말고 템플릿에서 생성하라 — 포크한 저장소는 사람이 직접 켜기 전까지
워크플로가 꺼져 있다.

`setup.sh`가 서명 키를 만들어 저장소 시크릿에 넣고, `config.json`을 채우고, 백업
시트를 쓰고, Pages를 켜고, 첫 실행을 시작한다. 이미 키가 있는 저장소는 건드리지 않는다.

**백업 시트를 보관하라.** 시크릿은 GitHub에서 다시 꺼낼 수 없으므로 그 종이가 키의
유일한 사본이다. 같은 32바이트를 세 가지로 적어서 하나가 틀리면 나머지가 잡아낸다.
종이를 믿기 전에 `scripts/backup/verify_sheet.py`를 돌려라.

## 기여를 추가하려면

편집할 것이 없다. 매 실행마다 본인이 작성해 머지된 공개 PR을 전부 찾아 GitHub API로
다시 확인한다. 하나를 빼려면 `badge.json`의 `exclude` 목록에 `owner/repo#123`을 넣는다.

## 키를 교체하려면

새 키로 서명한 크리덴셜은 그 키를 알리는 문서가 실제로 서빙되기 전까지 검증되지
않는다. 그래서 교체는 두 번의 실행으로 나뉜다.

```bash
gh workflow run publish -f identity_only=true   # 새 키가 담긴 did.json 먼저 게시
gh workflow run publish                          # 그다음 그 키로 서명·검증
```

## 갱신

`config.json`이 만료일 둘을 갖고 있다. 주간 cron이 하나라도 만료 30일 전이 되면
실패한다. 파일을 고쳐 푸시하면 된다.
