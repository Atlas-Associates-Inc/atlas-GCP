import type { AirlockDecision } from '../types.ts';
import { getAirlockProfile } from './profiles.ts';

const readVerbs = new Set(['get', 'list', 'query', 'read', 'describe', 'search', 'validate', 'status', 'inspect']);
const mutatingVerb = /^(?:(?:deploy|add|destroy|patch|exec|send|grant|publish|upload|insert|start|restart|kill|provision)(?:s|ed|ing)?|(?:creat|updat|delet|remov|execut|evaluat|invok|enabl|disabl|revok|replac|initializ)(?:e|es|ed|ing)|set(?:s|ting)?|reset(?:s|ting)?|init(?:s|ted|ting)?|appl(?:y|ies|ied|ying)|writ(?:e|es|ing|ten)|wrote|sent|run(?:s|ning)?|ran|stop(?:s|ped|ping)?|cancel(?:s|led|ling|ed|ing)?)$/;

export function evaluateTool(name: unknown, profileId?: string): AirlockDecision {
  if (typeof name !== 'string' || !/^[A-Za-z][A-Za-z0-9_.:/-]{0,127}$/.test(name)) {
    return { allowed: false, reason: 'Invalid or ambiguous tool name.' };
  }
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z])([A-Z][a-z])/g, '$1_$2')
    .toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (words.some((word, index) => mutatingVerb.test(word)
    && !(word === 'run' && ['cloud', 'dry'].includes(words[index - 1])))) {
    return { allowed: false, reason: 'A mutating or executable verb is prohibited.' };
  }
  if (!words.some((word) => readVerbs.has(word))) {
    return { allowed: false, reason: 'No explicitly allowed read-only verb.' };
  }
  if (profileId !== undefined) {
    const profile = getAirlockProfile(profileId);
    if (!profile) return { allowed: false, reason: 'Unknown airlock profile.' };
    const inProfile = words.some(word => profile.allowedTokens.includes(word))
      || profile.id === 'cloudrun' && words.some((word, index) => word === 'cloud' && words[index + 1] === 'run')
      || profile.id === 'developer-knowledge'
        && words.some((word, index) => word === 'developer' && words[index + 1] === 'knowledge');
    if (!inProfile) return { allowed: false, reason: 'Tool name is outside the selected airlock profile.' };
  }
  return { allowed: true, reason: 'Tool name passes the read-only verb policy.' };
}

export function isReadOnlyTool(name: unknown, profileId?: string): name is string {
  return evaluateTool(name, profileId).allowed;
}
