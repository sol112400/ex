const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const session = require("express-session");
const db = require("./database.js");
const multer = require("multer");

const app = express();

// 세션 설정
app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

// 정적 파일 제공
app.use("/css", express.static(path.join(__dirname, "css")));
app.use("/images", express.static(path.join(__dirname, "images")));
app.use("/js", express.static(path.join(__dirname, "js")));
app.use(express.static(path.join(__dirname, "html")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Body Parser 설정
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// HTML 라우트
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "html", "main.html")));
app.get("/signup.html", (req, res) => res.sendFile(path.join(__dirname, "html", "signup.html")));
app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "html", "login.html")));
app.get("/editprofile.html", (req, res) => res.sendFile(path.join(__dirname, "html", "editprofile.html")));

// 유틸리티 함수
const sendResponse = (res, status, message) => res.status(status).json({ message });

// 파일 저장 설정
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "uploads"));
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  },
});

const upload = multer({ storage });

// 회원가입 처리
app.post("/signup", async (req, res) => {
  const { user_id, username, nickname, email, password } = req.body;

  // 입력값 검증
  if (!user_id || !username || !email || !password) {
    return sendResponse(res, 400, "아이디, 이름, 이메일, 비밀번호는 필수 항목입니다.");
  }
  if (password.length < 8) {
    return sendResponse(res, 400, "비밀번호는 최소 8자 이상이어야 합니다.");
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return sendResponse(res, 400, "유효한 이메일 주소를 입력하세요.");
  }

  try {
    // 로그인 ID 중복 체크
    const sql = "SELECT * FROM User WHERE user_id = ?";
    db.query(sql, [user_id], async (err, idResults) => {
      if (err) {
        console.error("중복 검사 오류:", err);
        return sendResponse(res, 500, "서버 오류가 발생했습니다.");
      }

      if (idResults.length > 0) {
        return sendResponse(res, 400, "이미 사용 중인 아이디 입니다.");
      }

      // 회원가입 처리
      const hashedPassword = await bcrypt.hash(password, 10);
      const insertSql = `INSERT INTO User (user_id, username, nickname, email, password) VALUES (?, ?, ?, ?, ?)`;
      db.query(insertSql, [user_id, username, nickname, email, hashedPassword], (err, result) => {
        if (err) {
          console.error("회원가입 오류:", err);
          return sendResponse(res, 500, "회원가입 실패.");
        }
        console.log("회원가입 성공, 삽입된 데이터 ID:", result.insertId);
        sendResponse(res, 201, "회원가입 성공!");
      });
    });
  } catch (error) {
    console.error("회원가입 처리 중 오류:", error);
    sendResponse(res, 500, "서버 오류가 발생했습니다.");
  }
});

// 중복 체크 처리
app.post("/check-duplicate", (req, res) => {
  const { user_id } = req.body;

  if (!user_id) {
    return sendResponse(res, 400, "아이디를 입력하세요.");
  }

  const sql = "SELECT * FROM User WHERE user_id = ?";
  db.query(sql, [user_id], (err, results) => {
    if (err) {
      console.error("중복 검사 처리 중 오류:", err);
      return sendResponse(res, 500, "서버 오류가 발생했습니다.");
    }

    if (results.length > 0) {
      return sendResponse(res, 400, "이미 사용 중인 아이디 입니다.");
    }
    sendResponse(res, 200, "사용 가능한 아이디 입니다.");
  });
});

// 로그인 처리
app.post("/login", (req, res) => {
  const { user_id, password } = req.body;

  if (!user_id || !password) {
    return sendResponse(res, 400, "아이디와 비밀번호는 필수 항목입니다.");
  }

  const sql = `SELECT * FROM User WHERE user_id = ?`;
  db.query(sql, [user_id], async (err, results) => {
    if (err) {
      console.error("로그인 쿼리 오류:", err);
      return sendResponse(res, 500, "서버 오류가 발생했습니다.");
    }

    if (results.length === 0) {
      return sendResponse(res, 400, "아이디 또는 비밀번호가 일치하지 않습니다.");
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return sendResponse(res, 400, "아이디 또는 비밀번호가 일치하지 않습니다.");
    }

    // 세션에 사용자 정보 저장
    req.session.user = {
      id: user.user_id,
      username: user.username,
      nickname: user.nickname,
    };

    console.log("로그인 성공:", req.session.user); // 디버깅용 로그
    sendResponse(res, 200, "로그인 성공!");
  });
});

// 로그아웃 처리
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("로그아웃 중 오류 발생:", err);
      return res.status(500).json({ message: "로그아웃 중 오류가 발생했습니다." });
    }
    // 로그아웃 후 메인 페이지로 리디렉션
    res.clearCookie("connect.sid"); // 세션 쿠키 제거
    res.json({ message: "로그아웃 되었습니다. 메인 페이지로 이동합니다." }); // 메시지를 반환
  });
});

// 맛집 정보 가져오기
app.get("/restaurants", (req, res) => {
  const sql = "SELECT * FROM restaurants";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("맛집 정보 가져오기 오류:", err);
      return res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }
    res.json(results);
  });
});

// 맛집 상세 정보 API
app.get("/restaurant/:id", (req, res) => {
  const { id } = req.params;

  const sql = `
    SELECT 
      name, category, address, image_url, latitude, longitude, phone, 
      rating, review, hours, price 
    FROM restaurants 
    WHERE restaurants_id = ?`;
  
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("맛집 상세 정보 조회 오류:", err);
      return res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "해당 맛집을 찾을 수 없습니다." });
    }

    res.json(results[0]); // 첫 번째 결과 반환
  });
});

// 세션 상태 확인
app.get("/session-check", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// API: 사용자 정보 가져오기
app.get("/api/user", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }

  const sql = `
    SELECT username, nickname, email, picture, tier, review_count 
    FROM User 
    WHERE user_id = ?`;
  db.query(sql, [req.session.user.id], (err, results) => {
    if (err) {
      console.error("사용자 정보 조회 오류:", err);
      return res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }
    res.json(results[0]); // 필요한 사용자 정보 반환
  });
});

// 닉네임 변경 API
app.post("/api/user/nickname", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }

  const { nickname } = req.body;
  if (!nickname || nickname.trim() === "") {
    return res.status(400).json({ message: "유효한 닉네임을 입력해주세요." });
  }

  const sql = "UPDATE User SET nickname = ? WHERE user_id = ?";
  db.query(sql, [nickname, req.session.user.id], (err, results) => {
    if (err) {
      console.error("닉네임 변경 오류:", err);
      return res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }

    res.json({ success: true, message: "닉네임이 변경되었습니다." });
  });
});

// 비밀번호 변경 API
app.post("/api/user/password", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }

  const { newPassword, confirmPassword } = req.body;

  // 모든 필드가 제공되었는지 확인
  if (!newPassword || !confirmPassword) {
    return res.status(400).json({ message: "새 비밀번호와 비밀번호 확인을 모두 입력해주세요." });
  }

  // 새 비밀번호와 확인 비밀번호가 일치하지 않음
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ message: "새 비밀번호와 비밀번호 확인이 일치하지 않습니다." });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ message: "비밀번호는 최소 8자 이상이어야 합니다." });
  }

  // 새 비밀번호를 해싱하고 업데이트
  const hashedNewPassword = bcrypt.hashSync(newPassword, 10); // 비동기 -> 동기화 처리로 수정
  const sql = "UPDATE User SET password = ? WHERE user_id = ?";
  db.query(sql, [hashedNewPassword, req.session.user.id], (err) => {
    if (err) {
      console.error("비밀번호 변경 중 오류:", err);
      return res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }

    res.json({ success: true, message: "비밀번호가 성공적으로 변경되었습니다." });
  });
});

// 현재 비밀번호 확인 API
app.post("/api/user/verify-password", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }

  const { currentPassword } = req.body;

  if (!currentPassword) {
    return res.status(400).json({ message: "현재 비밀번호를 입력해주세요." });
  }

  const sql = "SELECT password FROM User WHERE user_id = ?";
  db.query(sql, [req.session.user.id], async (err, results) => {
    if (err) {
      console.error("현재 비밀번호 확인 오류:", err);
      return res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "현재 비밀번호가 일치하지 않습니다." });
    }

    res.json({ success: true, message: "현재 비밀번호가 확인되었습니다." });
  });
});

// 프로필 사진 업로드 API
app.post("/api/user/upload-photo", upload.single("profilePhoto"), (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }

  if (!req.file) {
    return res.status(400).json({ message: "파일 업로드에 실패했습니다." });
  }

  const photoUrl = `/uploads/${req.file.filename}`;

  const sql = "UPDATE User SET picture = ? WHERE user_id = ?";
  db.query(sql, [photoUrl, req.session.user.id], (err) => {
    if (err) {
      console.error("프로필 사진 저장 오류:", err);
      return res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }

    res.json({ success: true, photoUrl });
  });
});

// 회원탈퇴 API
app.delete("/api/delete-user", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
  }

  const sql = "DELETE FROM User WHERE user_id = ?";
  db.query(sql, [req.session.user.id], (err, result) => {
    if (err) {
      console.error("회원탈퇴 처리 중 오류:", err);
      return res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    // 세션 종료
    req.session.destroy((sessionErr) => {
      if (sessionErr) {
        console.error("세션 종료 오류:", sessionErr);
        return res.status(500).json({ message: "탈퇴 중 오류가 발생했습니다." });
      }
      res.clearCookie("connect.sid"); // 세션 쿠키 제거
      res.json({ message: "회원탈퇴가 완료되었습니다." });
    });
  });
});

// (아이디 찾기)아이디 찾기 처리
app.post("/find-user", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return sendResponse(res, 400, "이메일을 입력하세요.");
  }

  // 이메일로 사용자 검색
  const sql = "SELECT user_id FROM User WHERE email = ?";
  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error("아이디 찾기 오류:", err);
      return sendResponse(res, 500, "서버 오류가 발생했습니다.");
    }

    if (results.length === 0) {
      return sendResponse(res, 404, "이메일에 해당하는 사용자가 없습니다.");
    }

    const user = results[0];
    res.json({ success: true, user_id: user.user_id }); // user_id만 반환
  });
});


// (비밀번호 찾기)아이디와 이메일을 통한 사용자 확인 API
app.post("/validate-user", (req, res) => {
  const { userId, email } = req.body;

  if (!userId || !email) {
    return sendResponse(res, 400, "아이디와 이메일은 필수 항목입니다.");
  }

  const sql = "SELECT user_id FROM User WHERE user_id = ? AND email = ?";
  db.query(sql, [userId, email], (err, results) => {
    if (err) {
      console.error("아이디와 이메일 확인 오류:", err);
      return sendResponse(res, 500, "서버 오류가 발생했습니다.");
    }

    if (results.length === 0) {
      return sendResponse(res, 400, "아이디와 이메일이 일치하지 않습니다.");
    }

    res.json({ success: true, user_id: results[0].user_id });
  });
});

// (비밀번호 찾기)비밀번호 재설정 API
app.post("/reset-password", async (req, res) => {
  const { user_id, newPassword, confirmPassword } = req.body;

  // 필수 항목 체크
  if (!user_id || !newPassword || !confirmPassword) {
    return sendResponse(res, 400, "아이디, 새 비밀번호, 비밀번호 확인은 필수 항목입니다.");
  }

  if (newPassword !== confirmPassword) {
    return sendResponse(res, 400, "새 비밀번호와 비밀번호 확인이 일치하지 않습니다.");
  }

  if (newPassword.length < 8) {
    return sendResponse(res, 400, "비밀번호는 최소 8자 이상이어야 합니다.");
  }

  try {
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const sql = "UPDATE User SET password = ? WHERE user_id = ?";
    db.query(sql, [hashedNewPassword, user_id], (err) => {
      if (err) {
        console.error("비밀번호 변경 오류:", err);
        return res.status(500).json({ message: "서버 오류가 발생했습니다." });
      }

      res.json({ success: true, message: "비밀번호가 성공적으로 변경되었습니다." });
    });
  } catch (error) {
    console.error("비밀번호 변경 처리 중 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 서버 시작
app.listen(3000, () => {
  console.log("서버가 http://localhost:3000 에서 실행 중입니다.");
});
