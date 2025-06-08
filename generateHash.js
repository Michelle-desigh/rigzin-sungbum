const bcrypt = require('bcryptjs');

// 請將下面的密碼改成您想要設置的管理員密碼
const password = 'your-secure-password-here';
const saltRounds = 10;

bcrypt.hash(password, saltRounds, function(err, hash) {
    if (err) {
        console.error("Error hashing password:", err);
    } else {
        console.log("\n=== 密碼哈希生成成功 ===");
        console.log("您的密碼哈希值：");
        console.log(hash);
        console.log("\n請將此哈希值設置為環境變數 ADMIN_PASSWORD_HASH");
        console.log("======================\n");
    }
});