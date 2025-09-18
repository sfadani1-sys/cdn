/**
 * @file sfMetaScannerHeic.js
 * @description HEIC 파일의 ISOBMFF 박스(Box) 구조를 스캔하는 전문 스캐너 클래스입니다.
 *
 * HEIC 파일은 AVIF와 마찬가지로 ISOBMFF 컨테이너를 사용하며, '박스'라는 단위로 구성됩니다.
 * 이 스캐너는 각 박스를 순차적으로 식별하여 파일의 전체 구조를 보여줍니다.
 */
class sfMetaScannerHeic {
  /**
   * @description 주요 HEIC/ISOBMFF 박스 타입(FourCC) 정보입니다.
   */
  static HEIC_BOX_TYPES = {
    ftyp: "File Type Box (HEIC 형식 및 호환성 정보)",
    meta: "Meta Box (메타데이터 컨테이너)",
    hdlr: "Handler Box (메타 박스 내 데이터 종류 선언)",
    pitm: "Primary Item Reference Box (기본 이미지 항목 ID)",
    iloc: "Item Location Box (이미지 데이터 위치 정보)",
    iinf: "Item Info Box (이미지 항목 정보)",
    iprp: "Item Properties Box (이미지 속성 컨테이너)",
    ipco: "Item Property Container Box",
    ispe: "Image Spatial Extents (이미지 너비/높이)",
    pixi: "Pixel Information (픽셀당 비트 수)",
    hvcC: "HEVC Decoder Configuration (HEVC 코덱 설정)", // HEIC의 핵심
    colr: "Colour Information Box (색상 정보)",
    grid: "Image Grid (격자 이미지 레이아웃)",
    mdat: "Media Data Box (실제 압축 이미지 데이터)",
  };

  /**
   * @description HEIC 파일을 스캔하여 발견된 모든 박스의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[HEIC 박스 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];
        let i = 0;

        while (i < bytes.length - 8) {
          const boxSize = view.getUint32(i, false);
          const boxType = new TextDecoder().decode(bytes.slice(i + 4, i + 8));

          const description = this.HEIC_BOX_TYPES[boxType] || "알 수 없는 박스";
          if (logger)
            logger.trace(
              `[HEIC 박스 스캔] '${boxType}' 박스 발견 at offset=${i}, 크기: ${boxSize} bytes`
            );
          metadata.push({ key: boxType, value: description });

          if (boxType === "ispe" && boxSize >= 16) {
            const width = view.getUint32(i + 8, false);
            const height = view.getUint32(i + 12, false);
            metadata[metadata.length - 1].value += ` - ${width}x${height}`;
          }

          if (boxType === "ftyp" && boxSize >= 12) {
            const majorBrand = new TextDecoder().decode(
              bytes.slice(i + 8, i + 12)
            );
            metadata[
              metadata.length - 1
            ].value += ` - Major Brand: ${majorBrand}`;
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

        if (logger) logger.trace("[HEIC 박스 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
