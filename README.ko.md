# wantaekchoi.github.io

[English](README.md) — 개인 사이트: <https://wantaekchoi.github.io>

페이지 자체는 손으로 쓴 `index.html` 하나다. `.well-known/`과 `credentials/`
아래는 전부 `config.json`·`badge.json`에서 GitHub Actions가 매 푸시마다,
그리고 주 1회 렌더링하고 서명한다. 그 파일들은 손으로 고치지 않는다.

기여 크리덴셜에는 업스트림 메인테이너가 머지한 풀 리퀘스트가 들어간다.
워크플로가 매 실행마다 작성자와 머지 여부를 GitHub API로 다시 확인하고,
하나라도 어긋나면 발급을 거부한다.

`setup.sh`는 서명 키를 만들고 백업 시트를 출력한다. 한 번만 하는 절차이고,
키를 갈 때 참조하려고 남겨둔다.
