<?php
// Sending mail (plain text) via SMTP (PHPMailer). Configured only via environment variables (SMTP_*, MAIL_*).

use PHPMailer\PHPMailer\PHPMailer;

interface Mailer
{
    /** @return string|null error, null = sent */
    public function send(string $to, string $subject, string $body): ?string;
}

final class SmtpMailer implements Mailer
{
    public function send(string $to, string $subject, string $body): ?string
    {
        if (($problem = mail_config_problem()) !== null) {
            return $problem;
        }
        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = (string)SMTP_HOST;
            $mail->Port = (int)SMTP_PORT;
            $mail->Timeout = (int)SMTP_TIMEOUT;
            if (SMTP_SECURITY === 'tls') {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            } elseif (SMTP_SECURITY === 'starttls') {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            } else {
                $mail->SMTPSecure = '';
                $mail->SMTPAutoTLS = false; // dev mail catcher only (checked in mail_config_problem)
            }
            if ((string)SMTP_USERNAME !== '') {
                $mail->SMTPAuth = true;
                $mail->Username = (string)SMTP_USERNAME;
                $mail->Password = (string)SMTP_PASSWORD;
            }
            $mail->CharSet = PHPMailer::CHARSET_UTF8;
            $mail->setFrom((string)MAIL_FROM, (string)MAIL_FROM_NAME);
            $mail->addAddress($to);
            $mail->Subject = $subject;
            $mail->Body = $body;
            $mail->isHTML(false);
            $mail->XMailer = APP_NAME . ' ' . APP_VERSION;
            $mail->send();
            return null;
        } catch (Throwable $e) {
            // Never include credentials: PHPMailer's ErrorInfo only names the failing step.
            return 'SMTP: ' . ($mail->ErrorInfo !== '' ? $mail->ErrorInfo : $e->getMessage());
        }
    }
}

function mailer(): Mailer
{
    if (!isset($GLOBALS['PANAG_MAILER'])) {
        $GLOBALS['PANAG_MAILER'] = new SmtpMailer();
    }
    return $GLOBALS['PANAG_MAILER'];
}

/** Replace the mailer (tests). */
function set_mailer(?Mailer $mailer): void
{
    if ($mailer === null) {
        unset($GLOBALS['PANAG_MAILER']);
        return;
    }
    $GLOBALS['PANAG_MAILER'] = $mailer;
}

/** Send and record in mail_log. @return string|null error */
function send_logged_mail(string $kind, string $to, string $subject, string $body, ?string $maxSeverity = null, ?int $now = null): ?string
{
    $error = mailer()->send($to, $subject, $body);
    db()->prepare('INSERT INTO mail_log (created_at, kind, recipient, subject, max_severity, ok, error) VALUES (:t, :k, :r, :s, :m, :ok, :e)')
        ->execute([':t' => $now ?? time(), ':k' => $kind, ':r' => $to, ':s' => $subject, ':m' => $maxSeverity, ':ok' => $error === null ? 1 : 0, ':e' => $error]);
    return $error;
}
