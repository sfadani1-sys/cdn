/**
 * @file sfMetaScannerAvif.js
 * @description AVIF 파일의 ISOBMFF 박스(Box) 구조를 스캔하는 전문 스캐너 클래스입니다.
 *
 * AVIF 파일은 MP4와 동일한 ISOBMFF 컨테이너를 사용하며, '박스'라는 단위로 구성됩니다.
 * 이 스캐너는 각 박스를 순차적으로 식별하여 파일의 전체 구조를 보여줍니다.
 */
class sfMetaScannerAvif {
  /**
   * @description 주요 AVIF/ISOBMFF 박스 타입(FourCC) 정보입니다.
   */
  static AVIF_BOX_TYPES = {
    ftyp: "File Type Box (파일 형식 및 호환성 정보)",
    meta: "Meta Box (메타데이터 컨테이너)",
    hdlr: "Handler Box (메타 박스 내 데이터 종류 선언)",
    pitm: "Primary Item Reference Box (기본 이미지 항목 ID)",
    iloc: "Item Location Box (이미지 데이터 위치 정보)",
    iinf: "Item Info Box (이미지 항목 정보)",
    iprp: "Item Properties Box (이미지 속성 컨테이너)",
    ipco: "Item Property Container Box",
    ispe: "Image Spatial Extents (이미지 너비/높이)",
    pixi: "Pixel Information (픽셀당 비트 수)",
    av1C: "AV1 Codec Configuration (AV1 코덱 설정)",
    colr: "Colour Information Box (색상 정보)",
    grid: "Image Grid (격자 이미지 레이아웃)",
    mdat: "Media Data Box (실제 압축 이미지 데이터)",
  };

  /**
   * @description AVIF 파일을 스캔하여 발견된 모든 박스의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[AVIF 박스 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];
        let i = 0;

        // ISOBMFF 박스 루프
        while (i < bytes.length - 8) {
          // 최소 박스 헤더(8바이트) 크기
          // ISOBMFF는 Big Endian을 사용합니다.
          const boxSize = view.getUint32(i, false);
          const boxType = new TextDecoder().decode(bytes.slice(i + 4, i + 8));

          const description = this.AVIF_BOX_TYPES[boxType] || "알 수 없는 박스";
          if (logger)
            logger.trace(
              `[AVIF 박스 스캔] '${boxType}' 박스 발견 at offset=${i}, 크기: ${boxSize} bytes`
            );
          metadata.push({ key: boxType, value: description });

          // ispe 박스에서 너비와 높이 정보를 직접 추출하여 보여줍니다.
          if (boxType === "ispe" && boxSize >= 16) {
            const width = view.getUint32(i + 8, false);
            const height = view.getUint32(i + 12, false);
            metadata[metadata.length - 1].value += ` - ${width}x${height}`;
          }

          let nextBoxPos = i + boxSize;

          if (boxSize === 0) {
            // 박스 크기가 0이면 파일 끝까지를 의미
            if (logger)
              logger.trace(" -> 박스 크기가 0이므로 스캔을 종료합니다.");
            break;
          }
          if (boxSize === 1) {
            // 64비트 크기 필드 사용 (현재는 지원하지 않고 건너뜀)
            if (i + 16 > bytes.length) break;
            // JavaScript는 64비트 정수를 안전하게 다루기 어려우므로 일단은 스캔을 중단합니다.
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

        if (logger) logger.trace("[AVIF 박스 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
