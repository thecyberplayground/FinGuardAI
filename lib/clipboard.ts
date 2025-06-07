/**
 * Safe clipboard utility that works in both client and server environments
 */

export const copyToClipboard = (text: string): Promise<boolean> => {
  // Only run on client-side
  if (typeof window === 'undefined' || !navigator.clipboard) {
    console.warn('Clipboard not supported in this environment');
    return Promise.resolve(false);
  }
  
  return navigator.clipboard.writeText(text)
    .then(() => true)
    .catch((err) => {
      console.error('Failed to copy text: ', err);
      return false;
    });
};

export const isClipboardSupported = (): boolean => {
  return typeof window !== 'undefined' && !!navigator.clipboard;
};
