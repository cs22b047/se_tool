const express = require("express");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const bodyParser = require("body-parser");
const { exec } = require("child_process");
const path = require("path");

const app = express();
const SHELL_SCRIPT_PATH = "./devaic.sh"; // Relative path to the script
const UPLOAD_DIR = "input";

// Ensure the "input" directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Configure multer to rename uploaded files with .txt extension
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        const newFileName = `upload_${Date.now()}.txt`; // Save file as .txt
        cb(null, newFileName);
    }
});

const upload = multer({ storage });

app.use(cors());
app.use(bodyParser.json());

// **Upload file and analyze**
app.post("/upload", upload.single("file"), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
    }

    const filePath = req.file.path;
    console.log(`${SHELL_SCRIPT_PATH} ${filePath}`);

    exec(`${SHELL_SCRIPT_PATH} ${filePath}`, (error, stdout, stderr) => {
        fs.unlinkSync(filePath);

        if (error) {
            console.error(`Error executing script: ${error.message}`);
            return res.status(500).json({ error: "Error running analysis script" });
        }

        if (stderr) {
            console.error(`Script stderr: ${stderr}`);
            return res.status(500).json({ error: "Script execution error", details: stderr });
        }

        res.json({ report: stdout.trim() });
    });
});




// **Analyze pasted code**
app.post("/analyze", (req, res) => {
    const { code } = req.body;

    if (!code) {
        return res.status(400).json({ error: "No code provided" });
    }

    // Save pasted code as a .txt file and analyze it
    const tempFilePath = `input/pasted_${Date.now()}.txt`
    fs.writeFileSync(tempFilePath, code);

    console.log(`${SHELL_SCRIPT_PATH} ${tempFilePath}`);
    exec(`${SHELL_SCRIPT_PATH} ${tempFilePath}`, (error, stdout, stderr) => {
        fs.unlinkSync(tempFilePath);

        if (error) {
            console.error(`Error executing script: ${error.message}`);
            return res.status(500).json({ error: "Error running analysis script" });
        }

        if (stderr) {
            console.error(`Script stderr: ${stderr}`);
            return res.status(500).json({ error: "Script execution error", details: stderr });
        }

        res.json({ report: stdout.trim() });
    });
});

// **Start server**
const PORT = 5000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running at http://0.0.0.0:${PORT}`);
});