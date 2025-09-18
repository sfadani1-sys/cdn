/**
 * @file sfMetaScannerPng.js
 * @description PNG 파일의 모든 청크(Chunk)를 스캔하고 식별하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 PNG 파일의 바이너리 데이터를 직접 분석하여 파일의 전체 구조를
 * 청크 단위로 해부하는 저수준 분석 기능을 제공합니다.
 */
class sfMetaScannerPng {
  /**
   * @description 주요 PNG 청크 타입 정보입니다.
   */
  static PNG_CHUNK_TYPES = {
    IHDR: "Image Header (필수, 이미지 기본 정보)",
    PLTE: "Palette (색상 팔레트 정보)",
    IDAT: "Image Data (실제 이미지 데이터)",
    IEND: "Image Trailer (파일의 끝, 필수)",
    acTL: "Animation Control (APNG 애니메이션 제어)",
    fcTL: "Frame Control (APNG 프레임 제어)",
    fdAT: "Frame Data (APNG 프레임 데이터)",
    tEXt: "Textual Data (ISO/IEC 8859-1 텍스트 메타데이터)",
    zTXt: "Compressed Textual Data (압축된 텍스트 메타데이터)",
    iTXt: "International Textual Data (UTF-8 텍스트 메타데이터)",
    gAMA: "Gamma Correction (감마 값)",
    cHRM: "Primary Chromaticities (색도 값)",
    sRGB: "Standard RGB Color Space (sRGB 색 공간 정보)",
    pHYs: "Physical Pixel Dimensions (물리적 픽셀 크기)",
    tIME: "Last-modification Time (최종 수정 시간)",
  };

  /**
   * @description PNG 파일을 스캔하여 발견된 모든 청크의 목록을 반환합니다.
   * @static
   * @param {File} file - 분석할 File 객체.
   * @param {sfImageSanitizerLog} [logger] - 로그를 기록할 로거 인스턴스.
   * @returns {Promise<object>} 스캔 결과({ errors, metadata, skipped })를 담은 Promise.
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[PNG 청크 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const metadata = [];
        const errors = [];
        let i = 8; // PNG 시그니처(8바이트)를 건너뜁니다.

        while (i < bytes.length) {
          if (i + 8 > bytes.length) {
            errors.push("파일 끝에서 손상된 청크 헤더가 발견되었습니다.");
            break;
          }
          const view = new DataView(bytes.buffer, bytes.byteOffset + i);
          const length = view.getUint32(0); // 청크 데이터의 길이 (Big Endian)
          const type = new TextDecoder().decode(bytes.slice(i + 4, i + 8));

          const description = this.PNG_CHUNK_TYPES[type] || "알 수 없는 청크";
          if (logger)
            logger.trace(
              `[PNG 청크 스캔] '${type}' 청크 발견 at offset=${i}, 데이터 길이: ${length} bytes`
            );
          metadata.push({ key: type, value: description });

          // 기존의 텍스트 메타데이터 추출 로직을 여기에 통합합니다.
          if (["tEXt", "iTXt"].includes(type)) {
            const chunkData = bytes.slice(i + 8, i + 8 + length);
            const nullSeparatorIndex = chunkData.indexOf(0);
            if (nullSeparatorIndex > 0) {
              const keyword = new TextDecoder().decode(
                chunkData.slice(0, nullSeparatorIndex)
              );
              const text = new TextDecoder().decode(
                chunkData.slice(nullSeparatorIndex + 1)
              );
              // 상세 정보를 기존 로그에 추가합니다.
              const lastMeta = metadata[metadata.length - 1];
              lastMeta.value += ` - ${keyword}: ${text.substring(0, 50)}...`;
            }
          }

          if (type === "IEND") {
            if (logger)
              logger.trace(
                "[PNG 청크 스캔] IEND 청크 발견, 스캔을 종료합니다."
              );
            break; // 파일의 끝
          }

          const nextChunkPos = i + 12 + length; // 4(length)+4(type)+data(length)+4(CRC)
          if (nextChunkPos <= i || nextChunkPos > bytes.length) {
            errors.push(
              `'${type}' 청크의 길이가 비정상적이어서 스캔을 중단합니다.`
            );
            break;
          }
          i = nextChunkPos;
        }

        if (logger) logger.trace("[PNG 청크 스캔] 완료.");
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
