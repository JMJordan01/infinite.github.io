// Import necessary modules
import express from "express";
import http from "http";
import { Server } from "socket.io";
import path from "path";
import fs from "fs";
import multer from "multer";
import readline from "readline";
import { fileURLToPath } from "url";
import { exec } from "child_process";
import crypto from "crypto";
import cors from "cors";
import cookieParser from "cookie-parser";

// Setup __filename and __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize the Express app, HTTP server, and Socket.io
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Configure directories for uploads and logs
const uploadDir = path.join(process.cwd(), "uploads");
const logDir = path.join(process.cwd(), "logs");

ensureDirectories([uploadDir, logDir]);

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, uploadDir),
        filename: (req, file, cb) =>
            cb(null, `${Date.now()}-${file.originalname}`),
    }),
});

// Use CORS and cookie-parser middleware
app.use(cors());
app.use(cookieParser());

// Retrieve the secret username from environment variables
const secretUsername = process.env.admin || "admin"; // Admin username
const secret = process.env.admin || "3"; // Admin username

let messages = [];
let oneTimeLinks = {};
const chatLogFilename = path.join(logDir, `chat-log-${Date.now()}.html`);

initializeChatLog();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // Ensure static files are served

// Middleware to restrict access to admin-only routes
function adminOnly(req, res, next) {
    const adminCookie =
        req.cookies[
            "DO-NOT-SHARE-WITH-ANYONE----PEOPLE-WILL-STEAL-YOUR-ACCOUNT"
        ];

    if (adminCookie && adminCookie === secretUsername) {
        return next();
    } else {
        return res.status(403).send("Forbidden: Admins Only");
    }
}

// Define routes
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/public-chat", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "pchat.html"));
});

app.get("/99213", adminOnly, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/signup", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "signup.html"));
});

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/login", (req, res) => {
    const { username } = req.body;

    if (username === secretUsername) {
        res.cookie(
            "DO-NOT-SHARE-WITH-ANYONE----PEOPLE-WILL-STEAL-YOUR-ACCOUNT=",
            username,
            {
                httpOnly: true,
                maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week expiration
            },
        ); // Set the cookie
        res.status(200).json({ success: true });
    } else {
        res.status(401).json({ success: false, message: "Invalid username" });
    }

    if (username === secret) {
        res.cookie(
            "DO-NOT-SHARE-WITH-ANYONE----PEOPLE-WILL-STEAL-YOUR-ACCOUNT=",
            username,
            {
                httpOnly: true,
                maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week expiration
            },
        ); // Set the cookie
        res.status(200).json({ success: true });
    } else {
        res.status(401).json({ success: false, message: "Invalid username" });
    }
});

app.post("/upload", upload.single("file"), (req, res) => {
    if (!req.file) return res.status(400).send("No file uploaded.");
    res.send(formatFileInfo(req.file));
});

app.get("/download/:token", (req, res) => {
    const { token } = req.params;
    const fileInfo = oneTimeLinks[token];

    if (!fileInfo) {
        return res.status(404).send("Invalid or expired link.");
    }

    const filePath = path.join(uploadDir, fileInfo.filename);
    res.download(filePath, fileInfo.originalname, (err) => {
        if (!err) {
            delete oneTimeLinks[token];
        }
    });
});

app.get("/guidelines", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "TOS.html"));
});

app.get("/offline", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "downdetect.html"));
});

app.delete("/delete-message/:id", adminOnly, (req, res) => {
    const { id } = req.params;
    messages = messages.filter((msg, index) => index !== parseInt(id));
    io.emit("chat history", messages);
    res.status(200).send({ success: true });
});

// Socket.io handling
io.on("connection", (socket) => {
    socket.emit("chat history", messages);

    socket.on("chat message", (msg) => {
        handleNewMessage(msg, socket);
    });
});

function handleNewMessage(msg, socket) {
    const adminCookie = socket.request.headers.cookie?.includes(
        "DO-NOT-SHARE-WITH-ANYONE----PEOPLE-WILL-STEAL-YOUR-ACCOUNT=" +
            secretUsername,
    );
    const taggedMsg = {
        ...msg,
        tag: adminCookie ? "Admin" : "User",
    };

    messages.push(taggedMsg);
    io.emit("chat message", taggedMsg);
    appendToChatLog(formatMessageAsHtml(taggedMsg));
}

function formatMessageAsHtml({ username, message, timestamp, file, tag }) {
    const formattedMessage = convertLinks(message || "");
    const fileLinkHtml = file
        ? `<a href="/download/${generateOneTimeLink(file)}">${file.originalName} (${file.size} MB)</a>`
        : "";
    const tagStyle = tag === "Admin" ? "color: purple;" : "";
    return `<div><strong style="${tagStyle}">[${tag}] ${username}</strong>: ${formattedMessage} <span>(${timestamp})</span>${fileLinkHtml}</div>\n`;
}

function convertLinks(text) {
    const urlPattern =
        /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/gi;
    return text.replace(urlPattern, '<a href="$1" target="_blank">$1</a>');
}

function formatFileInfo(file) {
    return {
        fileName: file.filename,
        originalName: file.originalname,
        size: (file.size / (1024 * 1024)).toFixed(2),
    };
}

function initializeChatLog() {
    fs.writeFileSync(
        chatLogFilename,
        `<!DOCTYPE html><html><head><title>Chat Log</title></head><body><h1>Chat Log</h1><div id="messages">\n`,
    );
}

function appendToChatLog(html) {
    fs.appendFile(chatLogFilename, html, (err) => {
        if (err) console.error("Failed to write message to log file", err);
    });
}

function ensureDirectories(directories) {
    directories.forEach((dir) => {
        if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    });
}

function promptUser() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    rl.question("C:/>", (answer) => {
        handleShellInput(answer.trim().toLowerCase(), rl);
    });
}

function handleShellInput(input, rl) {
    const actions = {
        viewlog: () => openChatLogInBrowser(),
        clear: () => console.clear(),
        exit: () => {
            console.log("Exiting...");
            rl.close();
            return;
        },
    };

    if (actions[input]) {
        actions[input]();
    } else {
        console.log("Invalid command. Please type 'viewlog' or 'exit'.");
    }
    promptUser();
}

function openChatLogInBrowser() {
    const chatLogUrl = `http://localhost:3000/admin`;
    exec(`start ${chatLogUrl}`, (err) => {
        if (err) {
            console.error("Failed to open browser:", err);
        } else {
            console.log("Admin chat log opened in browser");
        }
    });
}

function generateOneTimeLink(file) {
    const token = crypto.randomBytes(16).toString("hex");
    oneTimeLinks[token] = {
        filename: file.filename,
        originalname: file.originalname,
    };
    return token;
}

// Start the server
server.listen(3000, () => {
    console.log("Server running on port 3000");
    console.clear();
    promptUser();
});
