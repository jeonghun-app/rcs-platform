# rcs-platform

[English](README.md)

GSMA RCS(Universal Profile) 서비스 플랫폼을 Go로 처음부터 구현합니다. IMS 코어(P-CSCF,
I-CSCF, S-CSCF, HSS), RCS 메시징 애플리케이션 서버, MSRP 릴레이, HTTP 파일 전송 서버를
각각 독립 서비스로 만들고, 명령 하나로 AWS에 배포합니다. 단말 설정은
[auto-configuration-server](https://github.com/jeonghun-app/auto-configuration-server)가
담당합니다.

> **상태: 개발 중.** [로드맵](#로드맵) 순서대로 서비스를 만들고 있으며, 아직 운영 환경에 쓸 수
> 있는 단계가 아닙니다.

## 서비스

| 서비스 | 역할 |
|---|---|
| `pcscf` | 단말의 SIP 진입점(TCP/TLS), 신원 확인, MSRP 앵커링 제어 |
| `icscf` | Diameter Cx로 S-CSCF 선택과 위치 조회 |
| `scscf` | 등록, IMS AKA·SIP Digest 인증, iFC 기반 애플리케이션 서버 라우팅 |
| `hss` | 가입자·자격 증명·서비스 프로파일, Diameter Cx/Sh, HTTP 프로비저닝 API |
| `rcs-as` | 1:1 채팅, 그룹 채팅, 단독 메시지, IMDN, 저장 후 전달 |
| `msrp-relay` | 네트워크 경계의 MSRP 미디어 앵커 |
| `ft-server` | HTTP 파일 전송 콘텐츠 서버(업로드, 이어 올리기, 다운로드), S3 저장 |
| `acs` | RCS 자동 설정, 별도 저장소 |

SIP, SDP, Diameter, MSRP, CPIM, IMDN, Milenage 구현은 모두 이 저장소에 있고, 런타임 의존성은
Go 표준 라이브러리와 AWS SDK뿐입니다. [docs/architecture.md](docs/architecture.md)와
[아키텍처 결정 기록](docs/adr/README.md)을 참고하세요.

## 빌드

Docker만 있으면 됩니다. Go는 고정된 컨테이너에서 실행됩니다.

```bash
make check     # 포맷, vet, 테스트, race detector, 빌드, 문서 링크, 개인정보 검사
make fuzz      # 모든 파서의 퍼즈 테스트
make vuln      # go mod verify + govulncheck
```

## 로드맵

1. 프로토콜 기반: 서비스 런타임, SIP 스택, SDP, Diameter, MSRP, CPIM/IMDN, Milenage
2. Cx와 프로비저닝 API를 갖춘 HSS
3. P-CSCF, I-CSCF, S-CSCF: 등록, 인증, 라우팅
4. MSRP 릴레이와 P-CSCF 미디어 앵커링
5. RCS 애플리케이션 서버: 기능 탐색, 1:1 채팅, 단독 메시지, IMDN, 저장 후 전달
6. 그룹 채팅
7. HTTP 파일 전송
8. ACS 연동, 전체 로컬 스택, AWS 인프라, 종단 간 검증

## 규격

규격은 문서 번호와 조항으로만 인용하고 원문은 옮기지 않습니다.
[docs/spec-references.md](docs/spec-references.md)를 참고하세요.

## 기여와 보안

[CONTRIBUTING.md](CONTRIBUTING.md)와 [SECURITY.md](SECURITY.md)를 참고하세요.

## 라이선스

[Apache License 2.0](LICENSE).
