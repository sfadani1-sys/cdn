/**
 * @file sfMetaScannerWebp.js
 * @description WebP 파일의 모든 청크(Chunk)를 스캔하고 식별하는 전문 스캐너 클래스입니다.
 *
 * WebP는 RIFF 컨테이너 형식을 기반으로 하며, 'RIFF' 헤더와 'WEBP' 식별자,
 * 그리고 다양한 청크들로 구성됩니다. 이 스캐너는 그 구조를 해부하여 보여줍니다.
 */
class sfMetaScannerWebp {
  /**
   * @description 주요 WebP 청크 타입(FourCC) 정보입니다.
   */
  static WEBP_CHUNK_TYPES = {
    "VP8 ": "Lossy Image Data (손실 압축 이미지 데이터)",
    VP8L: "Lossless Image Data (무손실 압축 이미지 데이터)",
    VP8X: "Extended File Features (애니메이션, 투명도, 메타데이터 등 확장 기능)",
    ANIM: "Animation Parameters (애니메이션 전역 정보)",
    ANMF: "Animation Frame (개별 애니메이션 프레임)",
    ALPH: "Alpha Channel Data (알파 채널/투명도 정보)",
    ICCP: "ICC Profile (색상 프로파일)",
    EXIF: "EXIF Metadata (EXIF 메타데이터)",
    "XMP ": "XMP Metadata (XMP 메타데이터)",
  };

  /**
   * @description WebP 파일을 스캔하여 발견된 모든 청크의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[WebP 청크 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];
        let i = 0;

        // 1. RIFF 헤더 검증
        const riffHeader = new TextDecoder().decode(bytes.slice(i, i + 4));
        const webpId = new TextDecoder().decode(bytes.slice(i + 8, i + 12));
        if (riffHeader === "RIFF" && webpId === "WEBP") {
          metadata.push({ key: "RIFF/WEBP", value: "WebP Container Header" });
          i += 12; // 헤더(12바이트)를 건너뜁니다.
        } else {
          errors.push("유효한 WebP(RIFF) 파일 헤더가 아닙니다.");
          resolve({ errors, metadata, skipped: false });
          return;
        }

        // 2. 청크 루프
        while (i < bytes.length - 8) {
          // 최소 청크 헤더(8바이트) 크기 이상 남았을 때
          const chunkId = new TextDecoder().decode(bytes.slice(i, i + 4));
          // RIFF는 Little Endian을 사용합니다.
          const chunkSize = view.getUint32(i + 4, true);

          const description =
            this.WEBP_CHUNK_TYPES[chunkId] || "알 수 없는 청크";
          if (logger)
            logger.trace(
              `[WebP 청크 스캔] '${chunkId}' 청크 발견 at offset=${i}, 데이터 길이: ${chunkSize} bytes`
            );
          metadata.push({ key: chunkId, value: description });

          // 다음 청크의 시작 위치 계산
          let nextChunkPos = i + 8 + chunkSize;

          // [중요] RIFF 청크는 데이터 크기가 홀수일 경우, 1바이트 패딩(padding)을 추가합니다.
          if (chunkSize % 2 !== 0) {
            nextChunkPos++;
          }

          if (nextChunkPos <= i || nextChunkPos > bytes.length) {
            errors.push(
              `'${chunkId}' 청크의 길이가 비정상적이어서 스캔을 중단합니다.`
            );
            break;
          }
          i = nextChunkPos;
        }

        if (logger) logger.trace("[WebP 청크 스캔] 완료.");
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
}
