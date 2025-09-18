/**
 * @file sfMetadataAnalyzer.js
 * @description [최종 아키텍처] 파일 형식별 전문 스캐너를 호출하는 100% 순수 디스패처 클래스입니다.
 *
 * 이 클래스는 이제 어떤 형식의 분석 로직도 직접 수행하지 않으며,
 * 오직 올바른 전문가(sfMetaScanner[Format].js)에게 작업을 위임하는 책임만 가집니다.
 *
 * [예외]
 * JPEG의 EXIF 데이터 분석 로직은 외부 라이브러리(exif-js)에 대한 의존성 때문에
 * 이 파일 내에 헬퍼 함수 형태로 유지됩니다. 하지만 이 로직조차도 JPEG 전문 스캐너인
 * sfMetaScannerJpeg.js에 의해 호출되어 사용되므로, 이 클래스의 디스패처 역할은 일관되게 유지됩니다.
 *
 * @dependency exif.min.js
 * @dependency sfMetaScannerJpeg.js
 * @dependency sfMetaScannerPng.js
 * @dependency sfMetaScannerGif.js
 * @dependency sfMetaScannerSvg.js
 * @dependency sfMetaScannerWebp.js
 * @dependency sfMetaScannerTiff.js
 * @dependency sfMetaScannerBmp.js
 * @dependency sfMetaScannerIco.js
 * @dependency sfMetaScannerAvif.js
 * @dependency sfMetaScannerHeic.js
 * @dependency sfMetaScannerJp2.js
 */
class sfMetadataAnalyzer {
  /**
   * @description 파일 형식에 맞는 메타데이터 분석을 시작하는 메인 진입점 함수입니다.
   *              이 함수는 마치 전화 교환원처럼, 들어온 파일의 형식(format)을 보고
   *              가장 적절한 전문가(sfMetaScanner)에게 전화를 연결해주는 역할을 합니다.
   * @param {File} file - 분석할 File 객체.
   * @param {string | null} format - '파일 구조 분석' 단계에서 식별된 실제 파일 형식.
   * @param {sfImageSanitizerLog} [logger] - 상세한 분석 과정을 기록하기 위한 로거 인스턴스.
   * @returns {Promise<object>} 각 전문 스캐너가 반환하는 표준화된 분석 결과 객체.
   */
  async analyze(file, format, logger) {
    switch (format) {
      case "jpeg":
        // JPEG는 구조(마커)와 내용(EXIF)을 모두 분석하는 가장 복잡한 전문가를 호출합니다.
        return sfMetaScannerJpeg.scan(file, logger);
      case "png":
      case "apng":
        return sfMetaScannerPng.scan(file, logger);
      case "gif":
        return sfMetaScannerGif.scan(file, logger);
      case "svg":
        return sfMetaScannerSvg.scan(file, logger);
      case "webp":
        return sfMetaScannerWebp.scan(file, logger);
      case "tiff":
        return sfMetaScannerTiff.scan(file, logger);
      case "bmp":
        return sfMetaScannerBmp.scan(file, logger);
      case "ico":
        return sfMetaScannerIco.scan(file, logger);
      case "avif":
        return sfMetaScannerAvif.scan(file, logger);
      case "heic":
        return sfMetaScannerHeic.scan(file, logger);
      case "jpeg2000":
        return sfMetaScannerJp2.scan(file, logger);
      default:
        // 어떤 전문가와도 연결할 수 없는 경우, 분석을 지원하지 않음을 알립니다.
        return {
          errors: [],
          warnings: [],
          metadata: [],
          skipped: true,
          reason: `이 형식(${
            format || "알 수 없음"
          })은 현재 메타데이터 분석을 지원하지 않습니다.`,
        };
    }
  }
}
