import nodemailer from 'nodemailer';
import config from '../config';

const sendEmail = async (to:string,html:string) => {
  try {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: config.NODE_ENV === 'production',
      auth: {
        user: "programmingherorubel@gmail.com",
        pass: "unfv iqsx bcid lclm",
      },
    });

    const mailOptions = {
      from: 'programmingherorubel@gmail.com',
      to,
      subject: "Reset Your Password with in 10 minutes",
      text: "Reset Your Password with in 10 minutes",
      html,
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.log(error)
  }
};

export default sendEmail;
