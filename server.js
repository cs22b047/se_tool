require("dotenv").config();
const express = require("express");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const bodyParser = require("body-parser");
const { exec } = require("child_process");
const path = require("path");

const app = express();
const UPLOAD_DIR = "input";

const { OpenAI } = require("openai");

const openai = new OpenAI({
    apiKey: process.env.OPENROUTER_API_KEY,
    baseURL: "https://openrouter.ai/api/v1"
});

// Ensure the input directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, `upload_${Date.now()}.txt`)
});

const upload = multer({ storage });

app.use(cors());
app.use(bodyParser.json());

app.use('/results', express.static(path.join(__dirname, 'results')));
app.use('/generated_file', express.static(path.join(__dirname, 'generated_file')));

// Function to get shell script path based on language
function getScriptPath(language) {
    switch (language.toLowerCase()) {
        case "python": return "./devaic.sh";
        case "cpp": return "./devaic_cpp.sh";
        case "java": return "./devaic_java.sh";
        default: return null;
    }
}

// Upload endpoint
app.post("/upload", upload.single("file"), (req, res) => {
    const language = req.body.language;
    const filePath = req.file?.path;

    if (!filePath || !language) {
        return res.status(400).json({ error: "File or language not provided" });
    }

    const scriptPath = getScriptPath(language);
    if (!scriptPath) {
        return res.status(400).json({ error: "Unsupported language" });
    }

    console.log(`${scriptPath} ${filePath}`);
    exec(`${scriptPath} ${filePath}`, (error, stdout, stderr) => {
        fs.unlinkSync(filePath);

        if (error || stderr) {
            console.error(error || stderr);
            return res.status(500).json({ error: "Script execution error", details: stderr });
        }

        res.json({ report: stdout.trim() });
    });
});







// Analyze pasted code endpoint
app.post("/analyze", (req, res) => {
    const { code, language } = req.body;

    if (!code || !language) {
        return res.status(400).json({ error: "Code or language not provided" });
    }

    const scriptPath = getScriptPath(language);
    if (!scriptPath) {
        return res.status(400).json({ error: "Unsupported language" });
    }
    const tempFileName = `pasted_${Date.now()}.txt`;
    const tempFilePath = `input/${tempFileName}`;
    fs.writeFileSync(tempFilePath, code);

    exec(`${scriptPath} ${tempFilePath}`, (error, stdout, stderr) => {
        fs.unlinkSync(tempFilePath);

        if (error || stderr) {
            console.error(error || stderr);
            return res.status(500).json({ error: "Script execution error", details: stderr });
        }

        res.json({ report: stdout.trim(),downloadPath: `results/DET_${tempFileName}`,downloadPathGen: `generated_file/INPUT_[2025-04-17_01-27-47]_pasted_1744833467509.txt` });
    });
});

app.listen(5000, "localhost", () => {
    console.log("Server running on http://localhost:5000");
});


app.post("/generate", async (req, res) => {
    const { code, language } = req.body;

    if (!code || !language) {
        return res.status(400).json({ error: "Code or language not provided" });
    }

    const prompt = `You are a secure coding assistant. Improve the following ${language} code by removing any potential security vulnerabilities while keeping functionality intact:\n\n${code}`;

    try {
        const completion = await openai.chat.completions.create({
            model: "openai/gpt-3.5-turbo",
            messages: [{ role: "user", content: prompt }],
            temperature: 0.2
        });

        const improvedCode = completion.choices[0].message.content;
        const outputFilename = `generated_code_${Date.now()}.txt`;
        const outputPath = path.join("generated_file", outputFilename);

        fs.writeFileSync(outputPath, improvedCode);

        res.json({ code: improvedCode, downloadPathGen: `generated_file/${outputFilename}` });

    } catch (err) {
        console.error("Error generating code:", err);
        res.status(500).json({ error: "Failed to generate secure code" });
    }
});