/**
 * @file sfMetaScannerJp2.js
 * @description JPEG 2000 (JP2) 파일의 박스(Box) 구조를 스캔하는 전문 스캐너 클래스입니다.
 *
 * JP2 파일은 고유한 시그니처 박스로 시작하고, 그 뒤에 ISOBMFF와 유사한 박스들이 이어지는 구조입니다.
 * 이 스캐너는 이 구조를 해부하여 파일의 구성 요소를 보여줍니다.
 */
class sfMetaScannerJp2 {
  /**
   * @description 주요 JP2 박스 타입(FourCC) 정보입니다.
   */
  static JP2_BOX_TYPES = {
    "jP  ": "JPEG 2000 Signature Box (파일 시그니처)",
    ftyp: "File Type Box (파일 형식 및 호환성 정보)",
    jp2h: "JP2 Header Box (모든 헤더 정보를 담는 상위 박스)",
    ihdr: "Image Header Box (이미지 너비, 높이 등 핵심 정보)",
    colr: "Colour Specification Box (색상 정보)",
    "res ": "Resolution Box (해상도 정보)",
    jp2c: "Contiguous Codestream Box (실제 압축 이미지 데이터)",
  };

  /**
   * @description JP2 파일을 스캔하여 발견된 모든 박스의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[JPEG 2000 박스 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];
        let i = 0;

        // 1. JPEG 2000 필수 시그니처 박스 검증 (12 bytes)
        const SIGNATURE = [
          0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87,
          0x0a,
        ];
        if (
          bytes.length < 12 ||
          !SIGNATURE.every((val, idx) => val === bytes[idx])
        ) {
          errors.push(
            "유효한 JPEG 2000 시그니처 박스가 파일의 시작 부분에 없습니다."
          );
          resolve({ errors, metadata, skipped: false });
          return;
        }
        metadata.push({ key: "jP  ", value: this.JP2_BOX_TYPES["jP  "] });
        i += 12;

        // 2. 나머지 박스 루프
        while (i < bytes.length - 8) {
          const boxSize = view.getUint32(i, false);
          const boxType = new TextDecoder().decode(bytes.slice(i + 4, i + 8));

          const description = this.JP2_BOX_TYPES[boxType] || "알 수 없는 박스";
          if (logger)
            logger.trace(
              `[JPEG 2000 박스 스캔] '${boxType}' 박스 발견 at offset=${i}, 크기: ${boxSize} bytes`
            );
          metadata.push({ key: boxType, value: description });

          // ihdr 박스에서 너비와 높이 정보를 직접 추출
          if (boxType === "ihdr" && boxSize >= 22) {
            const height = view.getUint32(i + 8, false);
            const width = view.getUint32(i + 12, false);
            metadata[metadata.length - 1].value += ` - ${width}x${height}`;
          }

          let nextBoxPos = i + boxSize;

          if (boxSize === 0) {
            if (logger)
              logger.trace(" -> 박스 크기가 0이므로 스캔을 종료합니다.");
            break;
          }
          if (boxSize === 1) {
            errors.push(
              `64비트 크기의 '${boxType}' 박스는 현재 지원하지 않습니다.`
            );
            break;
          }

          if (nextBoxPos <= i || nextBoxPos > bytes.length) {
            errors.push(
              `'${boxType}' 박스의 크기가 비정상적이어서 스캔을 중단합니다.`
            );
            break;
          }
          i = nextBoxPos;
        }

        if (logger) logger.trace("[JPEG 2000 박스 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
