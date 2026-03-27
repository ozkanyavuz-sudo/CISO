export interface QAItem {
  id: string;
  uid: string;
  question: string;
  answer: string;
  category: string;
  lastUpdated: string;
}

export interface MatchResult {
  question: string;
  matchedAnswer: string;
  confidence: number;
  originalQuestionId?: string;
  originalRowIdx?: number;
  reasoning?: string;
  status?: 'pending' | 'verified' | 'rejected';
}

export interface Questionnaire {
  id: string;
  uid: string;
  name: string;
  createdAt: string;
  status: 'pending' | 'processing' | 'completed';
  progress: number;
  results?: MatchResult[];
  originalData?: string;
  columnMapping?: {
    questionIdx: number;
    answerIdx: number;
  };
}

export interface Risk {
  id: string;
  uid: string;
  name: string;
  description: string;
  likelihood: 'Low' | 'Medium' | 'High' | 'Critical';
  mitigations: string;
  owner: string;
  archived: boolean;
  createdAt: string;
}

export interface PentestResult {
  id: string;
  uid: string;
  title: string;
  description: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  status: 'Open' | 'In Progress' | 'Resolved';
  source: 'Internal' | 'External';
  date: string;
  assignment?: string;
  remediationPlan?: string;
}
