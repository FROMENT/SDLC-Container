import { GoogleGenAI } from "@google/genai";
import { NEWS_SYSTEM_INSTRUCTION } from '../constants';

const apiKey = process.env.API_KEY || '';
const ai = new GoogleGenAI({ apiKey });

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
    console.error("Error generating news:", error);
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
        return "Sorry, I encountered an error processing your request.";
    }
}