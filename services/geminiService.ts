import { GoogleGenAI } from "@google/genai";
import { NEWS_SYSTEM_INSTRUCTION } from '../constants';

const apiKey = process.env.API_KEY || '';
const ai = new GoogleGenAI({ apiKey });

// Helper to check for quota errors
const isQuotaError = (error: any): boolean => {
  // Check standard Google API error structure
  if (error?.status === 'RESOURCE_EXHAUSTED' || error?.code === 429) return true;
  // Check if message contains 429
  if (error?.message && error.message.includes('429')) return true;
  return false;
};

export const generateNewsUpdate = async (newsContext: string, topicTitle: string): Promise<string> => {
  if (!apiKey) {
    return "API Key Missing: Cannot fetch live updates.";
  }

  try {
    const prompt = `Topic: ${topicTitle}\nContext focus: ${newsContext}\n\nProvide a "Live Security Intelligence Update" for this topic. Highlight 2-3 recent developments, CVEs, or tool updates from the last year.`;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        systemInstruction: NEWS_SYSTEM_INSTRUCTION,
        temperature: 0.4, 
      }
    });

    return response.text || "No news updates found.";
  } catch (error) {
    console.warn("Error generating news (likely quota):", error);
    if (isQuotaError(error)) {
       return "⚠️ Live updates temporarily unavailable due to high API traffic (Quota Limit Reached). Please try again later.";
    }
    return "⚠️ Unable to fetch live updates at this moment.";
  }
};

export const generateChatResponse = async (history: {role: string, parts: {text: string}[]}[], message: string): Promise<string> => {
    if (!apiKey) return "API Key missing.";

    try {
        const chat = ai.chats.create({
            model: 'gemini-2.5-flash',
            config: {
                systemInstruction: "You are a helpful Security Engineer. Answer questions about Kubernetes, Docker, and DevSecOps concisely.",
            },
            history: history
        });

        const result = await chat.sendMessage({ message });
        return result.text || "I couldn't generate a response.";
    } catch (e) {
        console.error(e);
        if (isQuotaError(e)) {
            return "I'm currently receiving too many requests (Quota Exceeded). Please try again in a minute.";
        }
        return "Sorry, I encountered an error processing your request.";
    }
}

export const generateStrideAnalysis = async (architecture: string): Promise<string> => {
  if (!apiKey) return "API Key missing.";

  try {
    const prompt = `
      Act as a Senior Security Architect specializing in Cloud Native and Kubernetes environments.
      Perform a STRIDE threat modeling analysis on the following architecture description provided by the user:
      
      "${architecture}"

      For each letter of STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), identify a specific threat scenario relevant to this architecture and provide a concrete mitigation strategy.

      Output the result **ONLY** as a Markdown table with the following columns:
      | STRIDE Category | Potential Threat Scenario | Mitigation Strategy |

      Keep the tone professional and technical.
    `;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
    });

    return response.text || "Unable to generate analysis.";
  } catch (e) {
    console.error("Error generating STRIDE analysis:", e);
    if (isQuotaError(e)) {
        return "⚠️ Analysis unavailable due to high traffic (Quota Exceeded). Please try again later.";
    }
    return "⚠️ Error generating threat model. Please try again.";
  }
};