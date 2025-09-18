/**
 * @file sfMetaScannerBmp.js
 * @description BMP(Bitmap) 파일의 헤더 정보를 스캔하고 분석하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 BMP 파일의 파일 헤더와 정보 헤더(DIB header)를 분석하여
 * 이미지의 크기, 색상 깊이, 압축 방식 등의 핵심 정보를 추출합니다.
 */
class sfMetaScannerBmp {
  /**
   * @description BMP 압축 방식 코드에 대한 설명입니다.
   */
  static BMP_COMPRESSION_METHODS = {
    0: "BI_RGB (압축 없음)",
    1: "BI_RLE8 (8-bit Run-Length Encoding)",
    2: "BI_RLE4 (4-bit Run-Length Encoding)",
    3: "BI_BITFIELDS (Bitfields)",
    4: "BI_JPEG (JPEG 이미지)",
    5: "BI_PNG (PNG 이미지)",
  };

  /**
   * @description BMP 파일을 스캔하여 분석 결과를 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[BMP 헤더 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];

        if (bytes.length < 54) {
          // 최소 헤더 크기 (파일 헤더 14 + 정보 헤더 40)
          errors.push("파일이 너무 작아 유효한 BMP 헤더를 포함할 수 없습니다.");
          resolve({ errors, metadata, skipped: true });
          return;
        }

        // 1. 파일 헤더 분석 (14 bytes)
        const magic = new TextDecoder().decode(bytes.slice(0, 2));
        if (magic === "BM") {
          metadata.push({ key: "Magic Number", value: `'BM' (Bitmap)` });
        } else {
          errors.push("유효한 BMP Magic Number('BM')가 아닙니다.");
          resolve({ errors, metadata, skipped: false });
          return;
        }
        // BMP는 Little Endian을 사용합니다.
        const fileSize = view.getUint32(2, true);
        const pixelDataOffset = view.getUint32(10, true);
        metadata.push({
          key: "File Size",
          value: `${fileSize.toLocaleString()} bytes`,
        });
        metadata.push({
          key: "Pixel Data Offset",
          value: `시작 위치 ${pixelDataOffset}`,
        });

        // 2. 정보 헤더(DIB Header) 분석
        const dibHeaderSize = view.getUint32(14, true);
        metadata.push({
          key: "Info Header Size",
          value: `${dibHeaderSize} bytes`,
        });

        const width = view.getInt32(18, true);
        const height = view.getInt32(22, true);
        metadata.push({ key: "Image Width", value: `${width} pixels` });
        metadata.push({ key: "Image Height", value: `${height} pixels` });

        const bpp = view.getUint16(28, true);
        metadata.push({ key: "Bits Per Pixel", value: `${bpp}-bit` });

        const compressionCode = view.getUint32(30, true);
        const compressionMethod =
          this.BMP_COMPRESSION_METHODS[compressionCode] || "알 수 없음";
        metadata.push({
          key: "Compression",
          value: `${compressionMethod} (코드: ${compressionCode})`,
        });

        // 3. 색상 테이블 존재 여부 추론
        if (bpp <= 8) {
          metadata.push({
            key: "Color Table",
            value: "색상 테이블(팔레트)이 존재할 가능성이 높음",
          });
        }

        if (logger) logger.trace("[BMP 헤더 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
