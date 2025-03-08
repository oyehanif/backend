const multer = require("multer");
const path = require("path");

const uploads = path.join(path.dirname(__dirname), "uploads");
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploads);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const lastDotIndex = file.originalname.lastIndexOf('.');
    
    const extension = file.originalname.substring(lastDotIndex + 1);
    cb(null, uniqueSuffix + '.'+extension);
  },
});

const upload = multer({ storage: storage });

module.exports = { upload };

