/**
 * @file sfMetaScannerSvg.js
 * @description SVG 파일의 텍스트 내용을 스캔하고 분석하는 전문 스캐너 클래스입니다.
 *
 * 이 클래스는 SVG 파일(XML 기반 텍스트)을 읽어 잠재적인 보안 위협 요소(예: <script> 태그)를
 * 탐지하고, <metadata> 태그의 내용을 추출하는 기능을 제공합니다.
 */
class sfMetaScannerSvg {
  /**
   * @description SVG 파일을 스캔하여 분석 결과를 반환합니다.
   * @static
   * @param {File} file - 분석할 File 객체.
   * @param {sfImageSanitizerLog} [logger] - 로그를 기록할 로거 인스턴스.
   * @returns {Promise<object>} 스캔 결과({ errors, metadata, skipped })를 담은 Promise.
   */
  static scan(file, logger) {
    return new Promise((resolve) => {
      if (logger) logger.trace("[SVG 콘텐츠 스캔] 시작...");
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target.result;
        const errors = [];
        const metadata = [];

        // 1. 보안 위협 검사: <script> 태그 존재 여부 확인
        if (text.toLowerCase().includes("<script")) {
          const message =
            "파일 내부에 잠재적으로 위험한 <script> 태그가 존재합니다.";
          if (logger) logger.trace(` -> 보안 위협 발견: ${message}`);
          errors.push(message);
        }

        // 2. 메타데이터 추출: <metadata> 태그 내용 확인
        const metadataMatch = text.match(
          /<metadata[^>]*>([\s\S]*?)<\/metadata>/i
        );
        if (metadataMatch && metadataMatch[1].trim()) {
          const extractedMeta = metadataMatch[1].trim();
          if (logger) logger.trace(` -> <metadata> 태그 발견, 내용 추출.`);
          const value =
            extractedMeta.length > 200
              ? extractedMeta.substring(0, 200) + "..."
              : extractedMeta;
          metadata.push({ key: "SVG Metadata", value });
        }

        if (logger) logger.trace("[SVG 콘텐츠 스캔] 완료.");
        resolve({ errors, metadata, skipped: false });
      };
      reader.onerror = () =>
        resolve({
          errors: ["파일 읽기 중 오류"],
          metadata: [],
          skipped: false,
        });
      // SVG는 텍스트 파일이므로 readAsText를 사용합니다.
      reader.readAsText(file);
    });
  }
}
