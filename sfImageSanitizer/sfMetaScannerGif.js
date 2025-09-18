/**
 * @file sfMetaScannerGif.js
 * @description GIF 파일의 모든 블록(Block)을 스캔하고 식별하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 GIF 파일의 바이너리 데이터를 직접 분석하여 파일의 전체 구조를
 * 블록 단위로 해부하는 저수준 분석 기능을 제공합니다.
 */
class sfMetaScannerGif {
  /**
   * @description GIF 블록 및 확장 타입 정보입니다.
   */
  static GIF_BLOCK_TYPES = {
    HEADER: "Header (GIF87a or GIF89a)",
    LSD: "Logical Screen Descriptor (전체 이미지 정보)",
    GCT: "Global Color Table (전역 색상표)",
    0x21: {
      // Extension Introducer
      0xf9: "Graphic Control Extension (애니메이션 제어)",
      0xfe: "Comment Extension (주석)",
      0x01: "Plain Text Extension (일반 텍스트)",
      0xff: "Application Extension (애플리케이션 정보, 예: 반복)",
    },
    0x2c: "Image Descriptor (개별 프레임 정보)",
    LCT: "Local Color Table (지역 색상표)",
    DATA: "Image Data (이미지 데이터 블록)",
    0x3b: "Trailer (파일의 끝)",
  };

  /**
   * @description GIF 파일을 스캔하여 발견된 모든 블록의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[GIF 블록 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const metadata = [];
        const errors = [];
        let i = 0;

        // 1. 헤더 (6바이트)
        const header = new TextDecoder().decode(bytes.slice(i, i + 6));
        if (header.startsWith("GIF")) {
          metadata.push({
            key: "HEADER",
            value: `${header} - ${this.GIF_BLOCK_TYPES["HEADER"]}`,
          });
          i += 6;
        } else {
          errors.push("유효한 GIF 파일 헤더가 아닙니다.");
          resolve({ errors, metadata, skipped: false });
          return;
        }

        // 2. 논리 화면 기술자 (7바이트)
        if (i + 7 <= bytes.length) {
          metadata.push({ key: "LSD", value: this.GIF_BLOCK_TYPES["LSD"] });
          const packedField = bytes[i + 4];
          const hasGCT = (packedField & 0x80) !== 0; // 최상위 비트가 1이면 GCT 존재
          i += 7;

          // 3. 전역 색상 테이블 (선택 사항)
          if (hasGCT) {
            const gctSize = 3 * 2 ** ((packedField & 0x07) + 1);
            metadata.push({
              key: "GCT",
              value: `${this.GIF_BLOCK_TYPES["GCT"]} (${gctSize} bytes)`,
            });
            i += gctSize;
          }
        }

        // 4. 데이터 블록 루프
        while (i < bytes.length) {
          const introducer = bytes[i];
          switch (introducer) {
            case 0x21: // 확장 블록
              const label = bytes[i + 1];
              const extInfo = this.GIF_BLOCK_TYPES[0x21][label];
              const key = extInfo
                ? `Ext(0x${label.toString(16).toUpperCase()})`
                : `Ext(Unknown)`;
              const value = extInfo || "알 수 없는 확장 블록";
              metadata.push({ key, value });
              if (logger)
                logger.trace(`[GIF 블록 스캔] '${value}' 발견 at offset=${i}`);

              // 기존 주석 추출 로직 통합
              if (label === 0xfe) {
                let commentData = this._extractSubBlockData(bytes, i + 2);
                metadata[
                  metadata.length - 1
                ].value += ` - ${new TextDecoder().decode(commentData)}`;
              }

              i = this._skipSubBlocks(bytes, i + 2);
              break;

            case 0x2c: // 이미지 기술자
              metadata.push({
                key: "IMG DESC",
                value: this.GIF_BLOCK_TYPES[0x2c],
              });
              if (logger)
                logger.trace(
                  `[GIF 블록 스캔] '${this.GIF_BLOCK_TYPES[0x2c]}' 발견 at offset=${i}`
                );
              // 이미지 기술자(9바이트) 건너뛰기
              i += 9;
              // TODO: Local Color Table 존재 여부 확인 및 건너뛰기
              // LZW 최소 코드 크기(1바이트) 건너뛰기
              i++;
              // 이미지 데이터 건너뛰기
              i = this._skipSubBlocks(bytes, i);
              break;

            case 0x3b: // 트레일러
              metadata.push({
                key: "TRAILER",
                value: this.GIF_BLOCK_TYPES[0x3b],
              });
              if (logger)
                logger.trace(
                  `[GIF 블록 스캔] '${this.GIF_BLOCK_TYPES[0x3b]}' 발견, 스캔을 종료합니다.`
                );
              i = bytes.length; // 루프 종료
              break;

            default:
              errors.push(
                `알 수 없는 블록 식별자(0x${introducer.toString(
                  16
                )}) at offset=${i}. 스캔을 중단합니다.`
              );
              i = bytes.length; // 루프 종료
              break;
          }
        }
        if (logger) logger.trace("[GIF 블록 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({
          errors: ["파일 읽기 중 오류"],
          metadata: [],
          skipped: false,
        });
      reader.readAsArrayBuffer(file);
    });
  }

  /**
   * @description GIF의 데이터 서브 블록들을 건너뛰고 다음 블록의 시작 위치를 반환합니다.
   * @private
   */
  static _skipSubBlocks(bytes, startIndex) {
    let i = startIndex;
    while (i < bytes.length && bytes[i] !== 0x00) {
      const blockSize = bytes[i];
      i += blockSize + 1;
    }
    return i + 1; // 0x00 종결자 다음 위치
  }

  /**
   * @description GIF의 데이터 서브 블록들에서 실제 데이터를 추출합니다.
   * @private
   */
  static _extractSubBlockData(bytes, startIndex) {
    const dataChunks = [];
    let i = startIndex;
    while (i < bytes.length && bytes[i] !== 0x00) {
      const blockSize = bytes[i];
      dataChunks.push(bytes.slice(i + 1, i + 1 + blockSize));
      i += blockSize + 1;
    }
    // Blob으로 합쳐서 처리하는 것이 큰 데이터에 효율적일 수 있으나, 여기서는 단순화
    const totalLength = dataChunks.reduce(
      (sum, chunk) => sum + chunk.length,
      0
    );
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of dataChunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }
}
