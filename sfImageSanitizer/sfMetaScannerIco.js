/**
 * @file sfMetaScannerIco.js
 * @description ICO(Icon) 파일의 헤더와 디렉토리 엔트리를 스캔하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 ICO 파일이 내부에 여러 이미지를 담는 컨테이너라는 점에 착안하여,
 * 헤더를 분석해 이미지 개수를 파악하고 각 이미지의 속성(크기, 색상 등)을 순차적으로 보여줍니다.
 */
class sfMetaScannerIco {
  /**
   * @description ICO 파일을 스캔하여 분석 결과를 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[ICO 구조 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];

        if (bytes.length < 6) {
          // 최소 헤더 크기
          errors.push("파일이 너무 작아 유효한 ICO 헤더를 포함할 수 없습니다.");
          resolve({ errors, metadata, skipped: true });
          return;
        }

        // 1. 헤더 분석 (6 bytes)
        // ICO 포맷은 Little Endian을 사용합니다.
        const reserved = view.getUint16(0, true);
        const imageType = view.getUint16(2, true);
        const imageCount = view.getUint16(4, true);

        if (reserved !== 0 || imageType !== 1) {
          errors.push("유효한 ICO 파일 시그니처가 아닙니다.");
          resolve({ errors, metadata, skipped: false });
          return;
        }
        metadata.push({ key: "ICO Header", value: "Windows Icon Resource" });
        metadata.push({
          key: "Image Count",
          value: `${imageCount}개의 이미지가 포함됨`,
        });
        if (logger) logger.trace(` -> 이미지 개수 확인: ${imageCount}`);

        // 2. 디렉토리 엔트리 분석 (각 16 bytes)
        for (let i = 0; i < imageCount; i++) {
          const entryOffset = 6 + i * 16;
          if (entryOffset + 16 > bytes.length) {
            errors.push(
              `이미지 #${i + 1}의 디렉토리 엔트리가 파일 크기를 벗어납니다.`
            );
            break;
          }

          if (logger)
            logger.trace(
              `[ICO Directory Entry #${i + 1}] 스캔 at offset=${entryOffset}`
            );

          let width = view.getUint8(entryOffset);
          let height = view.getUint8(entryOffset + 1);
          // ICO 명세: 너비/높이가 0이면 256을 의미합니다.
          if (width === 0) width = 256;
          if (height === 0) height = 256;

          const bpp = view.getUint16(entryOffset + 6, true);
          const sizeInBytes = view.getUint32(entryOffset + 8, true);
          const dataOffset = view.getUint32(entryOffset + 12, true);

          const description = `${width}x${height}, ${bpp}-bit, ${sizeInBytes.toLocaleString()} bytes at offset ${dataOffset}`;
          metadata.push({ key: `Image #${i + 1}`, value: description });
        }

        if (logger) logger.trace("[ICO 구조 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
