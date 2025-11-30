'use client';

import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Upload, Sparkles } from 'lucide-react';

export default function MailGuardAI() {
  const [emailText, setEmailText] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [eli12Mode, setEli12Mode] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState('');

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.eml')) {
      alert('Please upload a .eml file');
      e.target.value = '';
      return;
    }

    setUploadedFileName(file.name);

    try {
      const text = await file.text();
      setEmailText(text);
      console.log('File loaded successfully:', file.name);
    } catch (error) {
      console.error('File read error:', error);
      alert('Failed to read file. Please try again.');
      setUploadedFileName('');
    }
    
    e.target.value = '';
  };

  const analyzeEmail = async () => {
    if (!emailText.trim()) {
      alert('Please paste an email to scan');
      return;
    }

    setIsScanning(true);
    setResult(null);

    await new Promise(resolve => setTimeout(resolve, 1500));

    try {
      console.log('Starting analysis...');
      
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 1000,
          messages: [{
            role: 'user',
            content: `You are a security assistant. Evaluate the following email for malicious intent without using signature databases.

EMAIL:
${emailText}

TASK:
1) Verdict: Safe / Suspicious / High Risk
2) Plain-language explanation (1 sentence)
3) Evidence: up to 5 highlights (specific phrases or patterns from the email)
4) Tactics detected: list (e.g., urgency, extortion, suspicious attachments, obfuscated links)
5) Maliciousness probability (0-100)
6) Suggested user action (1 sentence)
7) Suggested SOC action (1 sentence)
8) ELI12 explanation: Explain this threat as if to a 12-year-old (1-2 sentences)

OUTPUT (JSON only, no markdown):
{
  "verdict": "",
  "probability": 0,
  "human_explanation": "",
  "evidence": [],
  "tactics": [],
  "user_action": "",
  "soc_action": "",
  "eli12_explanation": ""
}`
          }]
        })
      });

      console.log('API response status:', response.status);

      if (!response.ok) {
        const errorText = await response.text();
        console.error('API error response:', errorText);
        throw new Error(`API request failed: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('API response data:', data);
      
      const textContent = data.content.find((c: any) => c.type === 'text')?.text || '';
      console.log('Extracted text content:', textContent);
      
      let llmResult;
      try {
        const jsonMatch = textContent.match(/\{[\s\S]*\}/);
        if (!jsonMatch) {
          console.error('No JSON found in response');
          throw new Error('No JSON found in API response');
        }
        llmResult = JSON.parse(jsonMatch[0]);
        console.log('Parsed LLM result:', llmResult);
      } catch (e) {
        console.error('JSON parse error:', e);
        console.error('Text content was:', textContent);
        throw new Error('Failed to parse AI response');
      }

      if (!llmResult) {
        throw new Error('Failed to parse AI response');
      }

      const heuristics = computeHeuristics(emailText);
      console.log('Heuristics:', heuristics);
      
      let score = (
        0.2 * heuristics.urgency +
        0.2 * heuristics.payment +
        0.15 * heuristics.attachments +
        0.15 * heuristics.links +
        0.1 * heuristics.impersonation +
        0.2 * (llmResult.probability / 100)
      ) * 100;

      const zeroDay = llmResult.tactics.some((t: string) => 
        t.toLowerCase().includes('run') || 
        t.toLowerCase().includes('execute') || 
        t.toLowerCase().includes('disable')
      );
      if (zeroDay) score += 20;

      score = Math.min(100, Math.max(0, score));
      console.log('Final score:', score);

      let riskLevel = 'SAFE';
      let riskColor = 'text-green-600';
      let bgColor = 'bg-green-50';
      let icon = CheckCircle;

      if (score >= 60) {
        riskLevel = 'HIGH RISK';
        riskColor = 'text-red-600';
        bgColor = 'bg-red-50';
        icon = AlertTriangle;
      } else if (score >= 30) {
        riskLevel = 'SUSPICIOUS';
        riskColor = 'text-yellow-600';
        bgColor = 'bg-yellow-50';
        icon = AlertTriangle;
      }

      const finalResult = {
        score: Math.round(score),
        riskLevel,
        riskColor,
        bgColor,
        icon,
        ...llmResult,
        heuristicDetails: heuristics
      };

      console.log('Setting final result:', finalResult);
      setResult(finalResult);

    } catch (error: any) {
      console.error('Analysis error:', error);
      alert(`Analysis failed: ${error.message}\nCheck console for details.`);
    } finally {
      setIsScanning(false);
    }
  };

  const computeHeuristics = (text: string) => {
    const lower = text.toLowerCase();
    
    const urgencyWords = ['urgent', 'immediate', 'expire', 'suspend', 'verify now', 'act now', 'limited time', '24 hours', 'within', 'deadline'];
    const paymentWords = ['bitcoin', 'btc', 'crypto', 'wire transfer', 'gift card', 'payment', 'refund', 'invoice', 'purchase'];
    const attachmentPatterns = ['.exe', '.scr', '.bat', '.cmd', '.zip', '.rar', '.js', '.vbs', 'double extension'];
    const linkObfuscation = ['bit.ly', 'tinyurl', 'shortened', '@', 'http://', 'click here', 'verify account'];
    
    const urgency = urgencyWords.some(w => lower.includes(w)) ? 1 : 0;
    const payment = paymentWords.some(w => lower.includes(w)) ? 1 : 0;
    const attachments = attachmentPatterns.some(p => lower.includes(p)) ? 1 : 0;
    const links = linkObfuscation.some(p => lower.includes(p)) ? 1 : 0;
    
    const emailMatch = text.match(/from:?\s*[\w\.-]+@[\w\.-]+/i);
    const hasMismatch = emailMatch && !emailMatch[0].includes('legitimate-domain.com');
    const impersonation = hasMismatch ? 0.5 : 0;

    return { urgency, payment, attachments, links, impersonation };
  };

  const RiskIcon = result?.icon || Shield;

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="mb-12 pt-4">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-8 h-8 text-blue-600" />
            <h1 className="text-3xl font-bold text-gray-900">MailGuard.AI</h1>
          </div>
          <p className="text-gray-600">AI-Powered Email Security Scanner</p>
        </div>

        <div className="bg-white rounded-xl shadow-lg p-6 mb-8 border border-gray-100">
          <div className="flex items-start justify-between mb-3">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-1">
                Email Content
              </label>
              <p className="text-xs text-gray-500">
                Include: <span className="font-medium">From:</span> header, <span className="font-medium">Subject:</span> line, and full email body
              </p>
            </div>
            <div>
              <label className="cursor-pointer">
                <input
                  type="file"
                  accept=".eml"
                  onChange={handleFileUpload}
                  className="hidden"
                />
                <div className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-indigo-100 to-purple-100 hover:from-indigo-200 hover:to-purple-200 border-2 border-indigo-300 rounded-lg transition-all text-sm font-medium text-indigo-900">
                  <Upload className="w-4 h-4" />
                  Upload .eml
                </div>
              </label>
              {uploadedFileName && (
                <p className="text-xs text-green-600 mt-1 text-right">✓ {uploadedFileName}</p>
              )}
            </div>
          </div>
          <textarea
            value={emailText}
            onChange={(e) => setEmailText(e.target.value)}
            placeholder={`From: sender@example.com
Subject: Email subject here
Date: Mon, 1 Jan 2024 10:00:00

Email body content goes here...`}
            className="w-full h-48 p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none font-mono text-sm"
          />
          
          <div className="flex gap-3 mt-4">
            <button
              onClick={analyzeEmail}
              disabled={isScanning}
              className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 text-white py-3 px-6 rounded-lg font-semibold hover:from-blue-700 hover:to-blue-800 disabled:from-gray-400 disabled:to-gray-500 disabled:cursor-not-allowed transition-all shadow-md flex items-center justify-center gap-2"
            >
              {isScanning ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5" />
                  Scan Email
                </>
              )}
            </button>
            
            <button
              onClick={() => {
                setEmailText('');
                setResult(null);
                setUploadedFileName('');
              }}
              className="px-6 py-3 border-2 border-gray-300 rounded-lg hover:bg-gray-50 transition-colors font-semibold"
            >
              Clear
            </button>
          </div>
        </div>

        {result && (
          <div className="space-y-6">
            <div className={`${result.bgColor} rounded-xl shadow-lg p-8 border-2 ${result.riskColor.replace('text-', 'border-')}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <RiskIcon className={`w-12 h-12 ${result.riskColor}`} />
                  <div>
                    <div className="text-sm text-gray-600 mb-1">Risk Level</div>
                    <h2 className={`text-3xl font-bold ${result.riskColor}`}>
                      {result.riskLevel}
                    </h2>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-gray-600 mb-1">Threat Score</div>
                  <div className={`text-5xl font-bold ${result.riskColor}`}>
                    {result.score}<span className="text-2xl opacity-60">/100</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-lg p-6 border border-gray-100">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-bold text-gray-800">Analysis Results</h3>
                <button
                  onClick={() => setEli12Mode(!eli12Mode)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    eli12Mode 
                      ? 'bg-gradient-to-r from-purple-500 to-purple-600 text-white shadow-md' 
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  <Sparkles className="w-4 h-4" />
                  Simple Mode
                </button>
              </div>
              
              <div className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-5 mb-6 border-l-4 border-blue-500">
                <p className="text-gray-800 leading-relaxed font-medium">
                  {eli12Mode ? result.eli12_explanation : result.human_explanation}
                </p>
              </div>

              <div className="mb-6">
                <h4 className="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                  <span className="w-2 h-2 bg-red-500 rounded-full"></span>
                  Evidence Found
                </h4>
                <ul className="space-y-2">
                  {result.evidence.map((item: string, idx: number) => (
                    <li key={idx} className="text-gray-700 text-sm pl-4 py-2 bg-red-50 rounded-lg border-l-3 border-red-400">
                      {item}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                  <span className="w-2 h-2 bg-orange-500 rounded-full"></span>
                  Tactics Detected
                </h4>
                <div className="flex flex-wrap gap-2">
                  {result.tactics.map((tactic: string, idx: number) => (
                    <span key={idx} className="bg-gradient-to-r from-orange-100 to-red-100 border border-orange-300 text-orange-900 px-4 py-2 rounded-full text-sm font-medium shadow-sm">
                      {tactic}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-lg p-6 border border-gray-100">
              <h3 className="text-xl font-bold text-gray-800 mb-4">Recommended Actions</h3>
              
              <div className="space-y-4">
                <div className="border-l-4 border-blue-600 bg-gradient-to-r from-blue-50 to-blue-100 p-5 rounded-lg shadow-sm">
                  <h4 className="font-semibold text-blue-900 mb-2 flex items-center gap-2">
                    <span className="bg-blue-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-xs">1</span>
                    User Action
                  </h4>
                  <p className="text-blue-800 font-medium">{result.user_action}</p>
                </div>

                <div className="border-l-4 border-purple-600 bg-gradient-to-r from-purple-50 to-purple-100 p-5 rounded-lg shadow-sm">
                  <h4 className="font-semibold text-purple-900 mb-2 flex items-center gap-2">
                    <span className="bg-purple-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-xs">2</span>
                    SOC Action
                  </h4>
                  <p className="text-purple-800 font-medium">{result.soc_action}</p>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-r from-yellow-50 to-orange-50 border-2 border-yellow-300 rounded-xl p-5 text-sm text-gray-700 shadow-sm">
              <strong className="text-yellow-900">Disclaimer:</strong> This tool performs behavioral analysis using AI reasoning and heuristics. 
              It is not a substitute for enterprise email security solutions or sandboxing. Always follow your 
              organization's security protocols.
            </div>
          </div>
        )}

        {!result && !isScanning && (
          <div className="bg-white rounded-xl shadow-lg p-6 border border-gray-100">
            <h3 className="text-lg font-bold text-gray-800 mb-3">Test Sample</h3>
            <p className="text-gray-600 text-sm mb-4">Try scanning this example phishing email:</p>
            <div className="bg-gradient-to-br from-gray-50 to-gray-100 rounded-lg p-4 font-mono text-xs text-gray-700 border border-gray-200">
              <pre className="whitespace-pre-wrap">
{`From: security@paypa1-verify.com
Subject: URGENT: Your account will be suspended

Dear valued customer,

Your PayPal account has been locked due to suspicious activity. 
You must verify your identity within 24 hours or your account 
will be permanently suspended.

Click here to verify: http://bit.ly/paypal-verify-now

Please download and run the attached security_verification.exe 
file to complete the verification process.

This is an automated message. Do not reply.

PayPal Security Team`}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}