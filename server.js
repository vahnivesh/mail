/**
 * Zync OTP Server — Deploy on Render
 * Sends login OTP emails via Brevo (Sendinblue) SMTP/API
 * Routes:
 *   POST /send-otp   { email }         → generates & emails a 6-digit OTP
 *   POST /verify-otp { email, otp }    → verifies the OTP, returns { valid: true/false }
 */

const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const nodemailer = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── In-memory OTP store: { email → { otp, expiresAt } } ──
// For production with multiple instances use Redis instead.
const otpStore = new Map();

const OTP_EXPIRY_MS  = 5 * 60 * 1000;  // 5 minutes
const OTP_LENGTH     = 6;

// ── Brevo SMTP transporter ──
// BREVO_SMTP_USER = your full Brevo account login email (e.g. you@gmail.com)
// BREVO_SMTP_KEY  = the SMTP key from Brevo dashboard (SMTP & API → SMTP tab)
const transporter = nodemailer.createTransport({
  host:   'smtp-relay.brevo.com',
  port:   587,
  secure: false,
  auth: {
    user: process.env.BREVO_SMTP_USER,
    pass: process.env.BREVO_SMTP_KEY,
  },
  tls: { rejectUnauthorized: false },
});

// Verify SMTP connection on startup
transporter.verify((err, success) => {
  if (err) console.error('SMTP connection FAILED:', err.message);
  else     console.log('SMTP connection OK — ready to send emails');
});

// ── Middleware ──
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',  // set to your hosted domain e.g. https://zync.app
  methods: ['POST'],
}));
app.use(express.json());

// ── Helpers ──
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

function storeOTP(email, otp) {
  otpStore.set(email.toLowerCase(), {
    otp,
    expiresAt: Date.now() + OTP_EXPIRY_MS,
  });
}

function verifyOTP(email, otp) {
  const record = otpStore.get(email.toLowerCase());
  if (!record) return { valid: false, reason: 'No OTP found. Please request a new one.' };
  if (Date.now() > record.expiresAt) {
    otpStore.delete(email.toLowerCase());
    return { valid: false, reason: 'OTP expired. Please request a new one.' };
  }
  if (record.otp !== otp.trim()) {
    return { valid: false, reason: 'Incorrect OTP. Please try again.' };
  }
  otpStore.delete(email.toLowerCase()); // one-time use
  return { valid: true };
}

// ── Routes ──

// Health check
app.get('/', (req, res) => res.json({ status: 'Zync OTP Server running ✓' }));

// POST /send-otp
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ success: false, message: 'Invalid email address.' });
  }

  const otp = generateOTP();
  storeOTP(email, otp);

  const mailOptions = {
    from: `"Zync Authenticator" <${process.env.BREVO_SENDER_EMAIL}>`,
    to: email,
    subject: `${otp} is your Zync login code`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
      </head>
      <body style="margin:0;padding:0;background:#f4f4f5;font-family:'Segoe UI',Arial,sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 0;">
          <tr>
            <td align="center">
              <table width="440" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;border:1px solid #e4e4e7;overflow:hidden;">
                <!-- Header -->
                <tr>
                  <td style="background:#09090b;padding:28px 32px;text-align:center;">
                    <div style="display:inline-flex;align-items:center;gap:10px;">
                      <div style="width:36px;height:36px;background:#ffffff;border-radius:10px;display:inline-block;text-align:center;line-height:36px;font-weight:700;font-size:1.1rem;color:#09090b;vertical-align:middle;">Z</div>
                      <span style="color:#ffffff;font-weight:700;font-size:1.1rem;vertical-align:middle;margin-left:8px;">ZyncAuth</span>
                    </div>
                  </td>
                </tr>
                <!-- Body -->
                <tr>
                  <td style="padding:36px 32px 28px;">
                    <p style="margin:0 0 8px;font-size:0.78rem;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#a1a1aa;">Your login code</p>
                    <div style="background:#f4f4f5;border:1px solid #e4e4e7;border-radius:12px;padding:24px;text-align:center;margin:16px 0 24px;">
                      <span style="font-family:'Courier New',monospace;font-size:2.6rem;font-weight:700;letter-spacing:0.25em;color:#09090b;">${otp}</span>
                    </div>
                    <p style="margin:0 0 8px;font-size:0.9rem;color:#52525b;line-height:1.6;">
                      Enter this code in the Zync Authenticator app to complete your sign-in. This code expires in <strong>5 minutes</strong>.
                    </p>
                    <p style="margin:16px 0 0;font-size:0.8rem;color:#a1a1aa;line-height:1.5;">
                      If you didn't request this code, you can safely ignore this email. Someone may have entered your email by mistake.
                    </p>
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding:16px 32px;border-top:1px solid #e4e4e7;text-align:center;">
                    <p style="margin:0;font-size:0.72rem;color:#a1a1aa;">Made in India &nbsp;·&nbsp; © 2025 Zync Tech Pvt. Ltd.</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
    text: `Your Zync login code is: ${otp}\n\nThis code expires in 5 minutes.\n\nIf you didn't request this, please ignore this email.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}`);
    res.json({ success: true, message: 'OTP sent successfully.' });
  } catch (err) {
    console.error('Mail error:', err);
    res.status(500).json({ success: false, message: 'Failed to send OTP email. Please try again.' });
  }
});

// POST /verify-otp
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ valid: false, reason: 'Email and OTP are required.' });
  }
  const result = verifyOTP(email, otp);
  res.json(result);
});

app.listen(PORT, () => {
  console.log(`Zync OTP Server listening on port ${PORT}`);
});
