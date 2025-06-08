require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const fse = require('fs-extra');
const path = require('path');
const nodemailer = require('nodemailer'); // 引入 nodemailer
const bcrypt = require('bcryptjs'); // 引入 bcryptjs
const jwt = require('jsonwebtoken'); // 引入 jsonwebtoken
const app = express();
const port = process.env.PORT || 3001;

const googleDriveImageLinks = {
    rigzintsewangnorbu: [
	"https://drive.google.com/file/d/1xlAfJtd6ljzO6mSy3IgC9MOTxjkbYptp/view?usp=drive_link",
	"https://drive.google.com/file/d/15GyamXMO0Y8NPZEk86tHTNRZQOBY1tg6/view?usp=drive_link",
	"https://drive.google.com/file/d/1f44WczmbobeYarsE3kxo1pJ1rzrHLvgL/view?usp=drive_link",
	"https://drive.google.com/file/d/1wuJ2jRSTIc9AdHxNH8aOfaviq9RpnzxS/view?usp=drive_link",
	"https://drive.google.com/file/d/10RE_CzSIToBQKo25Aaq2C1GClZh6hTcT/view?usp=drive_link",
	"https://drive.google.com/file/d/1wUDwiYMXNI_8-SOWk-2GWECeSM3HxPG-/view?usp=drive_link",
	"https://drive.google.com/file/d/1XRLAb8xl8i7nl4ElsSxtF42kD1Wph78u/view?usp=drive_link",
	"https://drive.google.com/file/d/17sx5ZoUJIKQPxylWVLn1Kbq87IrJUm-G/view?usp=drive_link",
	"https://drive.google.com/file/d/1GciHHq1OSSuKOai565J0R_sZSCGo05J1/view?usp=drive_link",
	"https://drive.google.com/file/d/1T8GvX3C0V1dS8Nqam3Maycn36QVEk5vy/view?usp=drive_link",
	"https://drive.google.com/file/d/1F1Z7vr9lq4JJUas990dwHc2WKcgPLrnx/view?usp=drive_link"
    ],
    manuscripts: [
	"https://drive.google.com/file/d/1A3pecgRVVYaFG-FMXGuHYd2wb5zdT_Aq/view?usp=drive_link",
	"https://drive.google.com/file/d/1_ZZHpiR-N9JJzUKkFXju7PzdH2ERg_gY/view?usp=drive_link",
	"https://drive.google.com/file/d/1OlNeG1bzf3rWPv5DXK72vObkW5yPMfx9/view?usp=drive_link",
	"https://drive.google.com/file/d/1zTbRUT37Jam9w2NnFRQk9tzyIYly5dOv/view?usp=drive_link",
	"https://drive.google.com/file/d/1mIKMTpmQwssDCmbsUFh84kjou89DnfcK/view?usp=drive_link",
	"https://drive.google.com/file/d/1wLheKcRiLgqHV_o9Bj8wN4iiUZWl15cA/view?usp=drive_link",
	"https://drive.google.com/file/d/1Q0RbNjOtyGSgA8E34dGyp0jarhQZ5AO7/view?usp=drive_link",
	"https://drive.google.com/file/d/1g_CEbG06kkdCcY5s-yXOE7qqzkn9dfjK/view?usp=drive_link",
	"https://drive.google.com/file/d/15N_s-r-uIdgmOGBy2rLso14gxEG8PO-R/view?usp=drive_link",
	"https://drive.google.com/file/d/17NfxwXZ94HwVmkQn7sWYbvBlZTRXo6W5/view?usp=drive_link" 
  ]
};

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const dataDir = path.join(__dirname, 'data');
const runtimeDataFile = path.join(dataDir, 'all_runtime_documents.json');
const publicPath = path.join(__dirname, 'public'); // public 資料夾與 server.js 同級

// --- 伺服前端靜態檔案 ---
app.use(express.static(publicPath));

// --- 配置 Nodemailer ---
// 您需要使用一個真實的郵件服務提供商 (SMTP) 的帳戶信息
// 例如 Gmail, Outlook, SendGrid, Mailgun 等。
// 出於安全考慮，這些敏感信息 (郵箱用戶名、密碼或 API Key) 應該使用環境變數儲存，
// 而不是直接硬編碼在程式碼中。
// 在 Render 的 Environment Variables 中設置這些：
// MAIL_HOST (e.g., 'smtp.gmail.com')
// MAIL_PORT (e.g., 587 or 465)
// MAIL_SECURE (e.g., 'false' for port 587 with TLS, 'true' for port 465 with SSL)
// MAIL_USER (您的郵箱地址)
// MAIL_PASS (您的郵箱密碼或應用專用密碼)
// TO_EMAIL (您接收回報的郵箱地址 - rigzinsungbum@gmail.com)

const transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: parseInt(process.env.MAIL_PORT || "587"),
    secure: process.env.MAIL_SECURE === 'true', // true for 465, false for other ports
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
    },
    // 如果使用 Gmail，可能需要開啟 "允許低安全性應用程式存取權限"
    // 或者生成 "應用程式密碼" (App Password) 來代替您的常規密碼。
    // 對於其他服務如 SendGrid，通常使用 API Key。
    tls: {
        rejectUnauthorized: false // 在某些環境下可能需要，但要注意安全性
    }
});

// --- Meta Calculation Helper Function ---
function calculateMeta(tibetanContentHtml, chineseContentHtml, englishContentHtml = "") {
    const meta = {
        words: "N/A",
        pages: "N/A",
        readTime: "N/A",
        preview: "N/A"
    };

    let plainTibetan = "";
    if (tibetanContentHtml && typeof tibetanContentHtml === 'string') {
        plainTibetan = tibetanContentHtml.replace(/<[^>]+>/g, "").trim();
    }
    const tibetanSyllables = plainTibetan.split(/[་\s]+/).filter(s => s.trim().length > 0).length;

    let plainChinese = "";
    if (chineseContentHtml && typeof chineseContentHtml === 'string') {
        plainChinese = chineseContentHtml.replace(/<[^>]+>/g, "").trim();
    }
    const chineseChars = plainChinese.replace(/[^\u4E00-\u9FA5]/g, "").length;

    let plainEnglish = "";
    if (englishContentHtml && typeof englishContentHtml === 'string') {
        plainEnglish = englishContentHtml.replace(/<[^>]+>/g, "").trim();
    }
    const englishWords = plainEnglish.split(/\s+/).filter(s => s.trim().length > 0).length;

    if (plainTibetan.length > 0) {
        meta.preview = plainTibetan.substring(0, 80) + (plainTibetan.length > 80 ? '...' : '');
    } else if (plainChinese.length > 0) {
        meta.preview = plainChinese.substring(0, 80) + (plainChinese.length > 80 ? '...' : '');
    } else if (plainEnglish.length > 0) {
        meta.preview = plainEnglish.substring(0, 80) + (plainEnglish.length > 80 ? '...' : '');
    } else {
        meta.preview = "暫無預覽";
    }

    let wordsDescription = [];
    if (tibetanSyllables > 0) wordsDescription.push(`藏 ${tibetanSyllables} 音節`);
    if (chineseChars > 0) wordsDescription.push(`中 ${chineseChars} 字`);
    if (englishWords > 0) wordsDescription.push(`英 ${englishWords} 詞`);
    meta.words = wordsDescription.join(' | ') || "N/A";

    let totalReadTimeMinutes = 0;
    if (tibetanSyllables > 0) totalReadTimeMinutes += tibetanSyllables / 150; // 假設藏文閱讀速度
    if (chineseChars > 0) totalReadTimeMinutes += chineseChars / 250;   // 假設中文閱讀速度
    if (englishWords > 0) totalReadTimeMinutes += englishWords / 200;   // 假設英文閱讀速度

    if (totalReadTimeMinutes > 0) {
        meta.readTime = `閱讀約 ${Math.ceil(totalReadTimeMinutes)} 分鐘`;
        meta.pages = `${Math.ceil(Math.ceil(totalReadTimeMinutes) / 5)} 頁 (估算)`;
    }

    return meta;
}

// --- Data Store Initialization and Management ---
async function initializeDataStore(forceRebuild = false) {
    try {
        await fse.ensureDir(dataDir);
        const runtimeFileExists = await fse.pathExists(runtimeDataFile);

        if (!runtimeFileExists || forceRebuild) {
            console.log(forceRebuild ? "Forcing rebuild of runtime data file..." : `Runtime data file (${runtimeDataFile}) not found. Building from source JSON files...`);
            let allDocs = [];
            const files = await fse.readdir(dataDir);
            for (const file of files) {
                if (file.endsWith('.json') && file !== path.basename(runtimeDataFile)) {
                    const filePath = path.join(dataDir, file);
                    try {
                        const fileContent = await fse.readFile(filePath, 'utf-8');
                        // 嘗試修復可能的BOM問題和無效JSON字元
                        const cleanedContent = fileContent.replace(/^\uFEFF/, '').replace(/\u0000/g, '');
                        const fileData = JSON.parse(cleanedContent);

                        if (Array.isArray(fileData)) {
                            const processedFileData = fileData.map(doc => ({
                                ...doc,
                                meta: calculateMeta(doc.ContentTibetan, doc.ContentChinese, doc.ContentEnglish)
                            }));
                            allDocs = allDocs.concat(processedFileData);
                            console.log(`Loaded and processed ${processedFileData.length} documents from JSON: ${file}`);
                        } else if (typeof fileData === 'object' && fileData !== null) { // 單個文獻物件的 JSON 檔案
                             allDocs.push({
                                ...fileData,
                                meta: calculateMeta(fileData.ContentTibetan, fileData.ContentChinese, fileData.ContentEnglish)
                            });
                            console.log(`Loaded and processed 1 document from JSON: ${file}`);
                        } else {
                             console.warn(`Warning: JSON File ${filePath} is not a valid array or object and was skipped.`);
                        }
                    } catch (readErr) {
                        console.warn(`Warning: Could not process file ${filePath}: ${readErr.message}`);
                    }
                }
            }
            // 確保 ID 唯一性
            const uniqueDocs = [];
            const ids = new Set();
            for (const doc of allDocs) {
                if (doc.id && !ids.has(doc.id)) {
                    uniqueDocs.push(doc);
                    ids.add(doc.id);
                } else if (!doc.id) {
                    console.warn("Document without ID found, assigning temporary ID:", doc.chineseTitle || doc.tibetanTitle);
                    doc.id = 'temp_' + Date.now() + Math.random().toString(36).substring(2, 7);
                    uniqueDocs.push(doc);
                    ids.add(doc.id);
                } else {
                    console.warn(`Duplicate document ID found and skipped: ${doc.id}`);
                }
            }
            await fse.writeJson(runtimeDataFile, uniqueDocs, { spaces: 2 });
            console.log(`Initialized runtime data file at ${runtimeDataFile} with ${uniqueDocs.length} documents.`);
        } else {
            console.log(`Runtime data file found at ${runtimeDataFile}. Performing meta update check.`);
            let documents = await fse.readJson(runtimeDataFile);
            let updated = false;
            documents = documents.map(doc => {
                const currentMeta = doc.meta || {};
                const newMeta = calculateMeta(doc.ContentTibetan, doc.ContentChinese, doc.ContentEnglish);
                if (JSON.stringify(currentMeta) !== JSON.stringify(newMeta)) { // 比較 meta 是否有變化
                    console.log(`Updating meta for document ID: ${doc.id}`);
                    updated = true;
                    return { ...doc, meta: newMeta };
                }
                return doc;
            });
            if (updated) {
                await fse.writeJson(runtimeDataFile, documents, { spaces: 2 });
                console.log("Meta data updated for some documents in runtime file.");
            } else {
                console.log("No meta data updates needed for existing documents.");
            }
        }
    } catch (err) {
        console.error("Error initializing data store:", err);
        // 如果初始化失敗，可以嘗試提供一個空的陣列，避免服務完全崩潰
        if (!(await fse.pathExists(runtimeDataFile))) {
            await fse.writeJson(runtimeDataFile, [], { spaces: 2 });
            console.log(`Created an empty runtime data file due to initialization error.`);
        }
    }
}

async function getAllDocuments() {
    try {
        if (!(await fse.pathExists(runtimeDataFile))) {
            console.warn(`${runtimeDataFile} not found. Attempting to initialize...`);
            await initializeDataStore(true); // 強制重建如果檔案不存在
        }
        const documents = await fse.readJson(runtimeDataFile);
        return Array.isArray(documents) ? documents : []; // 確保返回陣列
    } catch (err) {
        console.error(`Error reading ${runtimeDataFile}: ${err.message}. Returning empty array.`);
        return [];
    }
}

async function saveAllDocuments(documents) {
    try {
        await fse.writeJson(runtimeDataFile, documents, { spaces: 2 });
        console.log(`Documents saved to ${runtimeDataFile}`);
    } catch (err) {
        console.error(`Error writing to ${runtimeDataFile}:`, err);
        throw err; // 重新拋出錯誤，讓調用者知道保存失敗
    }
}

// --- 環境變數中設置管理員帳密和 JWT 密鑰 ---
// 在 Render Environment Variables 中設置:
// ADMIN_USERNAME=your_admin_username
// ADMIN_PASSWORD_HASH=your_generated_bcrypt_hash  (不要直接存密碼)
// JWT_SECRET=a_very_strong_and_random_secret_key_for_jwt

// --- 登入 API 端點 ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // 從環境變數獲取正確的管理員用戶名和哈希後的密碼
    const adminUser = process.env.ADMIN_USERNAME;
    const adminPassHash = process.env.ADMIN_PASSWORD_HASH;
    const jwtSecret = process.env.JWT_SECRET;

    if (!adminUser || !adminPassHash || !jwtSecret) {
        console.error("管理員帳密或JWT密鑰未在環境變數中配置！");
        return res.status(500).json({ success: false, message: "伺服器配置錯誤。" });
    }

    if (username === adminUser && password && adminPassHash) {
        const isMatch = await bcrypt.compare(password, adminPassHash);
        if (isMatch) {
            // 密碼匹配，生成 JWT
            const token = jwt.sign(
                { userId: adminUser, role: 'admin' }, // payload
                jwtSecret,                            // secret key
                { expiresIn: '1h' }                  // token 有效期 1 小時
            );
            return res.json({ success: true, message: '登入成功', token: token });
        }
    }
    return res.status(401).json({ success: false, message: '用戶名或密碼錯誤。' });
});

// --- 中介軟體：驗證管理員 Token (用於保護需要管理員權限的 API) ---
function verifyAdminToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

    if (token == null) return res.sendStatus(401); // Unauthorized

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden
        if (user.role !== 'admin') return res.sendStatus(403); // Not an admin
        req.user = user;
        next();
    });
}

// --- API Endpoints ---
app.get('/api/documents', async (req, res) => {
    try {
        let documents = await getAllDocuments();
        // (可以添加 status 過濾等)
        res.json(documents);
    } catch (error) {
        res.status(500).json({ message: "Error fetching documents", error: error.message });
    }
}),
app.get('/api/image-links/:folder', async (req, res) => {
    const folder = req.params.folder;
    if (googleDriveImageLinks[folder]) {
        res.json(googleDriveImageLinks[folder]);
    } else {
        console.warn(`Warning: Image links for folder "${folder}" not found in server config.`);
        res.status(404).json({ message: '指定的圖片資料夾連結未找到' });
    }
});

// --- 保護需要管理員權限的 API 端點 ---
app.post('/api/documents', verifyAdminToken, async (req, res) => {
    try {
        const documents = await getAllDocuments();
        let newDocData = req.body;
        if (!newDocData.tibetanTitle && !newDocData.chineseTitle) { // 至少需要一個標題
            return res.status(400).json({ message: 'At least one title (Tibetan or Chinese) is required.' });
        }
        const newDoc = {
            id: 'doc_' + Date.now() + Math.random().toString(36).substring(2, 7),
            ...newDocData,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            status: newDocData.status || 'draft',
            meta: calculateMeta(newDocData.ContentTibetan, newDocData.ContentChinese, newDocData.ContentEnglish)
        };
        documents.unshift(newDoc); // 加到陣列開頭
        await saveAllDocuments(documents);
        res.status(201).json(newDoc);
    } catch (error) {
        res.status(500).json({ message: "Error creating document", error: error.message });
    }
});

app.put('/api/documents/:id', verifyAdminToken, async (req, res) => {
    try {
        let documents = await getAllDocuments();
        const docId = req.params.id;
        const updatedDocData = req.body;
        const docIndex = documents.findIndex(d => d.id === docId);

        if (docIndex > -1) {
            documents[docIndex] = {
                ...documents[docIndex],
                ...updatedDocData,
                id: docId, // 確保 ID 不變
                updatedAt: new Date().toISOString(),
                meta: calculateMeta(
                    updatedDocData.ContentTibetan !== undefined ? updatedDocData.ContentTibetan : documents[docIndex].ContentTibetan,
                    updatedDocData.ContentChinese !== undefined ? updatedDocData.ContentChinese : documents[docIndex].ContentChinese,
                    updatedDocData.ContentEnglish !== undefined ? updatedDocData.ContentEnglish : documents[docIndex].ContentEnglish
                )
            };
            await saveAllDocuments(documents);
            res.json(documents[docIndex]);
        } else {
            res.status(404).json({ message: 'Document not found for update' });
        }
    } catch (error) {
        res.status(500).json({ message: "Error updating document", error: error.message });
    }
});

app.delete('/api/documents/:id', verifyAdminToken, async (req, res) => {
    try {
        let documents = await getAllDocuments();
        const docId = req.params.id;
        const initialLength = documents.length;
        documents = documents.filter(d => d.id !== docId);

        if (documents.length < initialLength) {
            await saveAllDocuments(documents);
            res.status(200).json({ message: 'Document deleted successfully' });
        } else {
            res.status(404).json({ message: 'Document not found for deletion' });
        }
    } catch (error) {
        res.status(500).json({ message: "Error deleting document", error: error.message });
    }
});

// --- 新增 API 端點：處理錯誤回報 ---
app.post('/api/report-error', async (req, res) => {
    const { docId, pageUrl, context, description, userEmail } = req.body;

    if (!description || !description.trim()) {
        return res.status(400).json({ message: '問題描述不能為空。' });
    }
    
    // 設定收件人為 rigzinsungbum@gmail.com
    const toEmail = process.env.TO_EMAIL || 'rigzinsungbum@gmail.com';
    
    if (!process.env.MAIL_USER || !process.env.MAIL_PASS) {
         console.error("郵件配置不完整，無法發送錯誤回報。請檢查環境變數 MAIL_HOST, MAIL_PORT, MAIL_USER, MAIL_PASS。");
         return res.status(500).json({ message: '伺服器郵件配置錯誤，暫時無法提交回報。' });
    }

    const mailOptions = {
        from: `"才旺諾布全集系統回報" <${process.env.MAIL_USER}>`, // 發件人地址 (使用您配置的郵箱)
        to: toEmail, // 收件人地址 (rigzinsungbum@gmail.com)
        subject: `新錯誤回報 - 文獻: ${docId || 'N/A'}`,
        html: `
            <h2>才旺諾布全集閱讀系統 - 新錯誤回報</h2>
            <p><strong>回報時間:</strong> ${new Date().toLocaleString('zh-TW', { timeZone: 'Asia/Taipei' })}</p>
            <p><strong>回報者Email:</strong> ${userEmail || '未提供'}</p>
            <p><strong>問題頁面URL:</strong> ${pageUrl || 'N/A'}</p>
            <p><strong>文獻ID (若有):</strong> ${docId || 'N/A'}</p>
            <hr>
            <h3>問題相關內容:</h3>
            <pre style="background-color: #f0f0f0; padding: 10px; border-radius: 5px; white-space: pre-wrap;">${context || '未提供'}</pre>
            <hr>
            <h3>問題描述:</h3>
            <pre style="background-color: #f0f0f0; padding: 10px; border-radius: 5px; white-space: pre-wrap;">${description}</pre>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('錯誤回報郵件已發送:', mailOptions.subject);
        res.status(200).json({ message: '感謝您的回報！我們已收到您的訊息。' });
    } catch (error) {
        console.error('發送錯誤回報郵件失敗:', error);
        res.status(500).json({ message: '提交回報失敗，請稍後再試。' });
    }
});

// --- 新增 API 端點：獲取圖片列表 ---
app.get('/api/images/:folder', async (req, res) => {
    const folder = req.params.folder;
    const allowedFolders = ['rigzintsewangnorbu', 'manuscripts']; // 白名單資料夾
    
    if (!allowedFolders.includes(folder)) {
        return res.status(400).json({ message: '無效的資料夾名稱' });
    }
    
    const folderPath = path.join(publicPath, folder);
    
    try {
        const files = await fse.readdir(folderPath);
        const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
        const images = files.filter(file => {
            const ext = path.extname(file).toLowerCase();
            return imageExtensions.includes(ext);
        });
        
        res.json(images);
    } catch (error) {
        console.error(`無法讀取資料夾 ${folder}:`, error);
        res.status(500).json({ message: '無法讀取圖片資料夾' });
    }
});

// --- 根路徑和其他前端路由處理 ---
app.get('*', (req, res) => {
  const htmlFilePath = path.join(publicPath, 'rigzinsunbum5.0.html');
  if (fse.pathExistsSync(htmlFilePath)) {
    res.sendFile(htmlFilePath);
  } else {
    res.status(404).send("HTML file not found. Please ensure 'rigzinsunbum5.0.html' is in the public directory.");
  }
});

// --- Start the server ---
app.listen(port, async () => {
    await initializeDataStore();
    console.log(`Backend server for Rigzin Sunbum Web running on http://localhost:${port}`);
    console.log(`Frontend should be accessible at http://localhost:${port}`);
    console.log(`Static files are served from: ${publicPath}`);
    console.log(`Runtime data is being managed in: ${runtimeDataFile}`);
    
    // 顯示環境變數配置狀態
    console.log('\n環境變數配置檢查:');
    console.log(`- 管理員用戶名: ${process.env.ADMIN_USERNAME ? '✓ 已設置' : '✗ 未設置'}`);
    console.log(`- 管理員密碼哈希: ${process.env.ADMIN_PASSWORD_HASH ? '✓ 已設置' : '✗ 未設置'}`);
    console.log(`- JWT密鑰: ${process.env.JWT_SECRET ? '✓ 已設置' : '✗ 未設置'}`);
    console.log(`- 郵件主機: ${process.env.MAIL_HOST ? '✓ 已設置' : '✗ 未設置'}`);
    console.log(`- 郵件用戶: ${process.env.MAIL_USER ? '✓ 已設置' : '✗ 未設置'}`);
    console.log(`- 收件郵箱: ${process.env.TO_EMAIL || 'rigzinsungbum@gmail.com'}`);
});