const { Mailgen } = require("mailgen");
const nodemailer = require("nodemailer");

/**
 *
 * @param {{email: string; subject: string; mailGenContent: Mailgen.content;}} options
 */
const sendEmail = async (options) => {
  // Intialize Mailgen instace with default theme and branch configuration
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Chat App",
      link: "http://localhost:5173/",
    },
  });

  //   Generate xthe plaintext version of the e-mail (for clients that do not support HTML)
  const emailTextual = mailGenerator.generatePlaintext(options.mailGenContent);

  //   Generate an HTML email with the provided contents
  const emailHtml = mailGenerator.generate(options.mailGenContent);

  //  Create a nodemailer transporter using smtp which is responsible for sending email
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    // secure: false,
    auth: {
      user: process.env.SMTP_USERNAME,
      pass: process.env.SMTP_PASSWORD,
    },
  });

  const mail = {
    from: "mail.nathan21t19@gmail.com",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml,
  };

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    // As sending email is not strongly coupled to the business logic it is not worth to raise an error when email sending fails
    // So it's better to fail silently rather than breaking the app
    console.log(
      "Email service failed silently. Make sure you have provided your MAILTRAP credentials in the .env file"
    );
    console.log("Error: ", error);
  }
};

const emailVerificationMailgenContent = (username, verification) => {
  return {
    body: {
      name: username,
      intro: "Welcome to our app!, we're very excited to have you on board.",
      action: {
        instructions:
          "To verfiy your email please click on the following button:",
        button: {
          color: "#22BC66",
          text: "Verfiy your email",
          link: verification,
        },
      },
      outro:
        "Need help, or have questions? Just replay to this email, we'd love to help.",
    },
  };
};

const forgotPasswordMailgenContent = (username, resetPassword) => {
  return {
    body: {
      name: username,
      intro:
        "You have received this email because a password reset request for your account was received.",
      action: {
        instructions:
          "To reset your password please click on the following button:",
        button: {
          color: "#22BC66",
          text: "Reset your password",
          link: resetPassword,
        },
      },
      outro:
        "If you did not request a password reset, no further action is required on your part.",
    },
  };
};

module.exports = {
  sendEmail,
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
};