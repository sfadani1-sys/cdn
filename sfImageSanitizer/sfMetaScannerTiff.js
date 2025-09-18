/**
 * @file sfMetaScannerTiff.js
 * @description TIFF 파일의 IFD(Image File Directory)와 모든 태그를 스캔하는 전문 스캐너 클래스입니다.
 *
 * TIFF 파일은 헤더와 IFD(태그들의 목록)로 구성된 복잡한 구조를 가집니다.
 * 이 스캐너는 바이트 순서(Endianness)를 파악하고, IFD 오프셋을 따라가며 파일의 구조를 해부합니다.
 */
class sfMetaScannerTiff {
  /**
   * @description 주요 TIFF 태그 정보입니다. (전체 목록의 일부)
   */
  static TIFF_TAGS = {
    0x0100: { name: "ImageWidth", description: "이미지 너비" },
    0x0101: { name: "ImageLength", description: "이미지 높이 (세로)" },
    0x0102: { name: "BitsPerSample", description: "샘플 당 비트 수" },
    0x0103: { name: "Compression", description: "압축 방식" },
    0x0106: {
      name: "PhotometricInterpretation",
      description: "픽셀 구성 방식",
    },
    0x010f: { name: "Make", description: "제조사 정보" },
    0x0110: { name: "Model", description: "카메라 모델 정보" },
    0x0112: { name: "Orientation", description: "이미지 방향" },
    0x011a: { name: "XResolution", description: "수평 해상도" },
    0x011b: { name: "YResolution", description: "수직 해상도" },
    0x0131: { name: "Software", description: "사용된 소프트웨어" },
    0x0132: { name: "DateTime", description: "파일 변경 날짜/시간" },
    0x8769: { name: "ExifOffset", description: "EXIF IFD 오프셋" },
    0x8825: { name: "GPSInfo", description: "GPS IFD 오프셋" },
  };

  /**
   * @description TIFF 파일을 스캔하여 발견된 모든 태그의 목록을 반환합니다.
   * @static
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (logger) logger.trace("[TIFF 태그 스캔] 시작...");
        const bytes = new Uint8Array(e.target.result);
        const view = new DataView(bytes.buffer);
        const metadata = [];
        const errors = [];

        if (bytes.length < 8) {
          errors.push(
            "파일이 너무 작아 유효한 TIFF 헤더를 포함할 수 없습니다."
          );
          resolve({ errors, metadata, skipped: true });
          return;
        }

        // 1. 헤더 분석: 바이트 순서(Endianness) 및 첫 IFD 오프셋 확인
        const byteOrderMarker = view.getUint16(0, false); // Endianness는 모르므로 일단 Big-Endian으로 읽음
        const isLittleEndian = byteOrderMarker === 0x4949; // 'II'
        const isBigEndian = byteOrderMarker === 0x4d4d; // 'MM'

        if (!isLittleEndian && !isBigEndian) {
          errors.push(
            "유효한 TIFF 바이트 순서 마커('II' 또는 'MM')를 찾을 수 없습니다."
          );
          resolve({ errors, metadata, skipped: false });
          return;
        }
        if (logger)
          logger.trace(
            ` -> 바이트 순서 감지: ${
              isLittleEndian ? "Little Endian (II)" : "Big Endian (MM)"
            }`
          );

        const magicNumber = view.getUint16(2, isLittleEndian);
        if (magicNumber !== 42) {
          errors.push(
            `유효하지 않은 TIFF Magic Number(${magicNumber}) 입니다. (기대값: 42)`
          );
          resolve({ errors, metadata, skipped: false });
          return;
        }

        let currentIfdOffset = view.getUint32(4, isLittleEndian);
        if (logger) logger.trace(` -> 첫 번째 IFD 오프셋: ${currentIfdOffset}`);
        let ifdCount = 0;

        // 2. IFD 루프: 다음 IFD 오프셋이 0이 아닐 때까지 반복
        while (currentIfdOffset !== 0) {
          ifdCount++;
          if (logger)
            logger.trace(
              `[IFD #${ifdCount}] 스캔 시작 at offset=${currentIfdOffset}`
            );
          metadata.push({
            key: `IFD #${ifdCount}`,
            value: `Directory at offset ${currentIfdOffset}`,
          });

          if (currentIfdOffset + 2 > bytes.length) {
            errors.push(`IFD #${ifdCount} 오프셋이 파일 크기를 벗어납니다.`);
            break;
          }

          const entryCount = view.getUint16(currentIfdOffset, isLittleEndian);
          if (logger) logger.trace(` -> 태그 개수: ${entryCount}`);

          let entryOffset = currentIfdOffset + 2;

          // 3. 태그 루프: IFD 내의 모든 태그(Entry)를 순회
          for (let i = 0; i < entryCount; i++) {
            const tagId = view.getUint16(entryOffset, isLittleEndian);
            const tagInfo = this.TIFF_TAGS[tagId] || {
              name: `Unknown Tag (0x${tagId.toString(16)})`,
              description: "",
            };

            metadata.push({ key: tagInfo.name, value: tagInfo.description });
            entryOffset += 12; // 각 태그 엔트리는 12바이트
          }

          // 다음 IFD 오프셋을 읽어 루프를 계속할지 결정
          currentIfdOffset = view.getUint32(entryOffset, isLittleEndian);
          if (logger && currentIfdOffset !== 0)
            logger.trace(` -> 다음 IFD 오프셋: ${currentIfdOffset}`);
        }

        if (logger) logger.trace("[TIFF 태그 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({ errors: ["파일 읽기 중 오류"], metadata, skipped: false });
      reader.readAsArrayBuffer(file);
    });
  }
}
