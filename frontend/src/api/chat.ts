import { apiClient } from './client';

export interface ChatMessage {
  id: number;
  user_id: number;
  session_id: string;
  sender: 'user' | 'assistant';
  message: string;
  context?: Record<string, any>;
  created_at: string;
}

export interface ChatResponse {
  reply: string;
  user_message: string;
  context?: Record<string, any>;
  created_at: string;
  history: ChatMessage[];
}

export const sendChatMessageApi = async (
  message: string,
  context?: Record<string, any>,
  sessionId: string = 'default'
): Promise<ChatResponse> => {
  const response = await apiClient.post<ChatResponse>('/chat', {
    message,
    context,
    session_id: sessionId,
  });
  return response.data;
};

export const getChatHistoryApi = async (sessionId: string = 'default'): Promise<ChatMessage[]> => {
  const response = await apiClient.get<ChatMessage[]>('/chat/history', {
    params: { session_id: sessionId },
  });
  return response.data;
};
