const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();  // Load environment variables

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ✅ MySQL Database Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'your_password',
    database: 'student_attendance'
});

db.connect(err => {
    if (err) throw err;
    console.log("✅ Database Connected...");
});

const SECRET_KEY = "your_secret_key";  // Change this in production

// ✅ Validate ID Format (Same for Student, Staff, and HOD)
function isValidIDFormat(id) {
    return /^[0-9]{2}[A-Z]{1}[0-9]{2}[A-Z]{1}[0-9]{4}$/.test(id);
}

// 🚀 **1️⃣ Student Registration API**
app.post('/stu_signup', async (req, res) => {
    const { name, studentId, branch, section, year, password } = req.body;

    if (!isValidIDFormat(studentId)) {
        return res.status(400).json({ message: "❌ Invalid Student ID format! Use format: 24X35A6608" });
    }

    try {
        db.query('SELECT * FROM students WHERE student_id = ?', [studentId], async (err, result) => {
            if (err) return res.status(500).json({ message: "Database Error!" });

            if (result.length > 0) {
                return res.status(400).json({ message: "❌ Student ID already registered!" });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            db.query(
                `INSERT INTO students (name, student_id, branch, section, year, password) VALUES (?, ?, ?, ?, ?, ?)`, 
                [name, studentId, branch, section, year, hashedPassword], 
                (err) => {
                    if (err) return res.status(500).json({ message: "Error registering student" });
                    res.json({ message: "✅ Student Registered Successfully!" });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ message: "⚠️ Server Error" });
    }
});

// 🔐 **2️⃣ Student Login API**
app.post('/stu_signin', async (req, res) => {
    const { studentId, password } = req.body;

    db.query('SELECT * FROM students WHERE student_id = ?', [studentId], async (err, result) => {
        if (err) return res.status(500).json({ message: "⚠️ Server Error" });

        if (result.length === 0) {
            return res.status(401).json({ message: "❌ Invalid Student ID" });
        }

        const student = result[0];
        const isPasswordMatch = await bcrypt.compare(password, student.password);

        if (!isPasswordMatch) {
            return res.status(401).json({ message: "❌ Incorrect Password" });
        }

        const token = jwt.sign({ studentId: student.student_id }, SECRET_KEY, { expiresIn: "3h" });

        res.status(200).json({ message: "✅ Login Successful", token, redirect: "stu_dashboard.html" });
    });
});

// 🚀 **3️⃣ Staff Registration API**
app.post('/staff_signup', async (req, res) => {
    const { name, staffId, branch, password } = req.body;

    if (!isValidIDFormat(staffId)) {
        return res.status(400).json({ message: "❌ Invalid Staff ID format!" });
    }

    try {
        db.query('SELECT * FROM faculty WHERE staff_id = ?', [staffId], async (err, result) => {
            if (err) return res.status(500).json({ message: "Database Error!" });

            if (result.length > 0) {
                return res.status(400).json({ message: "❌ Staff ID already registered!" });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            db.query(
                `INSERT INTO faculty (name, staff_id, branch, password) VALUES (?, ?, ?, ?)`, 
                [name, staffId, branch, hashedPassword], 
                (err) => {
                    if (err) return res.status(500).json({ message: "Error registering staff" });
                    res.json({ message: "✅ Staff Registered Successfully!" });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ message: "⚠️ Server Error" });
    }
});

// 🔐 **4️⃣ Staff Login API**
app.post('/staff_signin', async (req, res) => {
    const { staffId, password } = req.body;

    db.query('SELECT * FROM faculty WHERE staff_id = ?', [staffId], async (err, result) => {
        if (err) return res.status(500).json({ message: "⚠️ Server Error" });

        if (result.length === 0) {
            return res.status(401).json({ message: "❌ Invalid Staff ID" });
        }

        const staff = result[0];
        const isPasswordMatch = await bcrypt.compare(password, staff.password);

        if (!isPasswordMatch) {
            return res.status(401).json({ message: "❌ Incorrect Password" });
        }

        const token = jwt.sign({ staffId: staff.staff_id }, SECRET_KEY, { expiresIn: "3h" });

        res.status(200).json({ message: "✅ Login Successful", token, redirect: "staff_dashboard.html" });
    });
});

// 🚀 **5️⃣ HOD Registration API**
app.post('/hod_signup', async (req, res) => {
    const { name, hodId, branch, password } = req.body;

    try {
        db.query('SELECT * FROM hods WHERE hodid = ?', [hodId], async (err, result) => {
            if (err) return res.status(500).json({ message: "Database Error!" });

            if (result.length > 0) {
                return res.status(400).json({ message: "❌ HOD ID already registered!" });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            db.query(
                `INSERT INTO hods (name, hodid, branch, password) VALUES (?, ?, ?, ?)`, 
                [name, hodId, branch, hashedPassword], 
                (err) => {
                    if (err) return res.status(500).json({ message: "Error registering HOD" });
                    res.json({ message: "✅ HOD Registered Successfully!" });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ message: "⚠️ Server Error" });
    }
});

// 🔐 **6️⃣ HOD Login API**
app.post("/hod_signin", async (req, res) => {
    const { hodId, branch, password } = req.body; // ✅ Ensure correct variable names

    if (!hodId || !branch || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        const sql = "SELECT * FROM hods WHERE hodid = ?";
        db.query(sql, [hodId], async (err, results) => {
            if (err) {
                console.error("Database Error:", err);
                return res.status(500).json({ error: "Database error" });
            }
            
            if (results.length === 0) {
                return res.status(401).json({ error: "Invalid HOD ID or password" });
            }

            const isMatch = await bcrypt.compare(password, results[0].password);
            if (!isMatch) {
                return res.status(401).json({ error: "Invalid HOD ID or password" });
            }

            const token = jwt.sign({ hodId: results[0].hod_id }, "your_secret_key", { expiresIn: "1h" });
            res.status(200).json({ token, message: "Login successful" });
        });
    } catch (error) {
        console.error("Server Error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


// 🚀 **Start Server**
app.listen(5000, () => {
    console.log("✅ Server running on port 5000...");
});
 