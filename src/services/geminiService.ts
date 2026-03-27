import { QAItem, MatchResult } from "../types";
import { GoogleGenAI, Type } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });

async function delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function matchQuestion(
  newQuestion: string,
  knowledgeBase: QAItem[],
  retryCount = 0
): Promise<MatchResult> {
  if (retryCount > 3) {
    return {
      question: newQuestion,
      matchedAnswer: "Rate limit exceeded after multiple retries. Please try again in a few minutes.",
      confidence: 0,
    };
  }

  if (knowledgeBase.length === 0) {
    return {
      question: newQuestion,
      matchedAnswer: "No knowledge base entries found. Please add data to your Knowledge Base first.",
      confidence: 0,
    };
  }

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.1-flash-lite-preview",
      contents: `
        You are a security expert. Match the following incoming security question to the best answer in our knowledge base.
        
        Incoming Question: "${newQuestion}"
        
        Knowledge Base:
        ${(knowledgeBase || []).slice(0, 30).map((item: any, index: number) => {
          const q = item.question || "Untitled Question";
          const a = item.answer || "No answer provided.";
          const isDoc = item.category === 'Document' || q.startsWith('Document:') || q.startsWith('PDF:');
          return `${index + 1}. ${isDoc ? 'SOURCE DOCUMENT' : 'Q'}: ${q}\n   ${isDoc ? 'CONTENT' : 'A'}: ${a.slice(0, 3000)}${a.length > 3000 ? '... [TRUNCATED]' : ''}`;
        }).join("\n\n")}
        
        Return the best match in JSON format with the following structure:
        {
          "matchedAnswer": "the exact answer from the KB, or a direct quote/summary from a source document",
          "confidence": number (0 to 1),
          "reasoning": "why this is a match"
        }
        
        If no good match exists (confidence < 0.4), provide a suggested answer based on your general knowledge but prefix it with "[AI Suggestion]".
      `,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            matchedAnswer: { type: Type.STRING },
            confidence: { type: Type.NUMBER },
            reasoning: { type: Type.STRING },
          },
          required: ["matchedAnswer", "confidence", "reasoning"],
        },
      },
    });

    const text = response.text;
    if (!text) {
      throw new Error("AI returned an empty response.");
    }

    const cleanedText = text.replace(/```json|```/g, "").trim();
    const result = JSON.parse(cleanedText);

    return {
      question: newQuestion,
      matchedAnswer: result.matchedAnswer || "No match found.",
      confidence: result.confidence || 0,
      reasoning: result.reasoning
    };
  } catch (error: any) {
    console.error("Error matching question:", error);
    
    // Check for rate limit (429)
    if (error.message?.includes("429") || error.status === 429 || error.message?.includes("RESOURCE_EXHAUSTED")) {
      console.log(`Rate limit hit, retrying in ${Math.pow(2, retryCount) * 1000}ms...`);
      await delay(Math.pow(2, retryCount) * 1000);
      return matchQuestion(newQuestion, knowledgeBase, retryCount + 1);
    }
    
    return {
      question: newQuestion,
      matchedAnswer: `Error: ${error.message || "The AI encountered an error while processing this question."}`,
      confidence: 0,
    };
  }
}

export async function processQuestionnaire(
  questions: { text: string; originalRowIdx: number }[],
  knowledgeBase: QAItem[],
  onProgress?: (progress: number) => void
): Promise<MatchResult[]> {
  const results: MatchResult[] = [];
  const batchSize = 1; // Process 1 at a time to be safest with free tier limits
  
  for (let i = 0; i < questions.length; i++) {
    const match = await matchQuestion(questions[i].text, knowledgeBase);
    results.push({
      ...match,
      originalRowIdx: questions[i].originalRowIdx
    });
    
    if (onProgress) {
      onProgress(Math.round(((i + 1) / questions.length) * 100));
    }
    
    // Add a small delay between requests even if successful to stay under per-minute limits
    if (i < questions.length - 1) {
      await delay(1000); 
    }
  }
  
  return results;
}
