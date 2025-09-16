class sfImageSanitizerLba {
  constructor(elementId) {
    this.element = document.getElementById(elementId);
    this.fileInput = document.getElementById("sf-image-upload");
    this.dropArea = document.getElementById("sf-image-drop-area");
    this.messageInput = document.getElementById("sf-message");
    this.embedButton = document.getElementById("sf-embed-button");
    this.originalImage = document.getElementById("sf-original-image");
    this.embeddedImageCanvas = document.getElementById("sf-embedded-image");
    this.embeddedImageContext = this.embeddedImageCanvas.getContext("2d");
    this.image = null;

    this.setupEventListeners();
  }

  setupEventListeners() {
    this.fileInput.addEventListener("change", this.handleFileSelect.bind(this));
    this.dropArea.addEventListener("dragover", this.handleDragOver.bind(this));
    this.dropArea.addEventListener("drop", this.handleDrop.bind(this));
    this.embedButton.addEventListener("click", this.embedMessage.bind(this));

    ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
      this.dropArea.addEventListener(eventName, this.preventDefaults, false);
    });
  }

  preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  handleFileSelect(event) {
    const file = event.target.files[0];
    this.loadImage(file);
  }

  handleDragOver(event) {
    this.dropArea.classList.add("highlight");
  }

  handleDrop(event) {
    this.dropArea.classList.remove("highlight");
    const file = event.dataTransfer.files[0];
    this.loadImage(file);
  }

  loadImage(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      this.image = new Image();
      this.image.onload = () => {
        this.originalImage.src = this.image.src;
        this.embeddedImageCanvas.width = this.image.width;
        this.embeddedImageCanvas.height = this.image.height;
        this.embeddedImageContext.drawImage(this.image, 0, 0);
        this.embedButton.disabled = false;
      };
      this.image.src = event.target.result;
    };
    reader.readAsDataURL(file);
  }

  embedMessage() {
    const message = this.messageInput.value;
    if (!message) {
      alert("숨길 메시지를 입력하세요.");
      return;
    }

    const imageData = this.embeddedImageContext.getImageData(
      0,
      0,
      this.image.width,
      this.image.height
    );
    const data = imageData.data;
    const binaryMessage = this.stringToBinary(message);
    const messageLength = binaryMessage.length;

    if (messageLength > data.length * 0.75) {
      alert(
        "메시지가 너무 깁니다. 더 작은 메시지를 사용하거나 더 큰 이미지를 선택하세요."
      );
      return;
    }

    let dataIndex = 0;
    for (let i = 0; i < messageLength; i++) {
      let bit = parseInt(binaryMessage[i]);
      if (dataIndex % 4 !== 3) {
        // 알파 채널은 건너뜁니다.
        data[dataIndex] = (data[dataIndex] & 0xfe) | bit;
      } else {
        i--; // 알파 채널을 건너뛰었으므로 메시지 인덱스를 유지합니다.
      }
      dataIndex++;
      if (dataIndex >= data.length) break;
    }

    this.embeddedImageContext.putImageData(imageData, 0, 0);
  }

  stringToBinary(str) {
    let binary = "";
    for (let i = 0; i < str.length; i++) {
      let charCode = str.charCodeAt(i);
      let binaryChar = charCode.toString(2).padStart(8, "0");
      binary += binaryChar;
    }
    return binary;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  new sfImageSanitizerLba("sf-image-sanitizer-lba");
});
