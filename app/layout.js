import './globals.css'

export const metadata = {
  title: 'MailGuard.AI - Email Security Scanner',
  description: 'AI-Powered Email Security Scanner',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}


