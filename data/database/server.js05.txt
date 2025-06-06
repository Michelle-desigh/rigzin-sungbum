const express = require('express');
const cors = require('cors');
const fse = require('fs-extra');
const path = require('path');
const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const dataDir = path.join(__dirname, 'data');
const runtimeDataFile = path.join(dataDir, 'all_runtime_documents.json');
const publicPath = path.join(__dirname, 'public'); // public 資料夾與 server.js 同級

// --- 伺服前端靜態檔案 ---
app.use(express.static(publicPath));

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

// --- API Endpoints ---
app.get('/api/documents', async (req, res) => {
    try {
        let documents = await getAllDocuments();
        // (可以添加 status 過濾等)
        res.json(documents);
    } catch (error) {
        res.status(500).json({ message: "Error fetching documents", error: error.message });
    }
});

app.post('/api/documents', async (req, res) => {
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

app.put('/api/documents/:id', async (req, res) => {
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

app.delete('/api/documents/:id', async (req, res) => {
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
});