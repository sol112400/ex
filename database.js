const mysql = require('mysql');

// MySQL 데이터베이스 연결 설정
const db = mysql.createConnection({
    host: 'localhost',       // 데이터베이스 호스트
    user: 'root',            // 사용자 이름
    password: 'root',            // 비밀번호
    database: 'term'   // 사용할 데이터베이스 이름
});

// 데이터베이스 연결 확인
db.connect((err) => {
    if (err) {
        console.error('데이터베이스 연결 실패:', err);
    } else {
        console.log('데이터베이스 연결 성공!');
    }
});

module.exports = db;
