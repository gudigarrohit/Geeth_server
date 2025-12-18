import dotenv from "dotenv";
dotenv.config(); // 👈 make sure .env is loaded before we read process.env

import nodemailer from "nodemailer";



console.log("EMAIL_USER:", process.env.EMAIL_USER);
console.log("EMAIL_PASS set:", !!process.env.EMAIL_PASS);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export default async function sendEmailOtp(email, otp) {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP code is ${otp}`,
  });
}
