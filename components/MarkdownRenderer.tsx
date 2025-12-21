import React from 'react';

interface Props {
  content: string;
}

// A lightweight markdown renderer.
// Handles headers, code blocks, bold/code inline, lists, and tables.
export const MarkdownRenderer: React.FC<Props> = ({ content }) => {
  if (!content) return null;

  const lines = content.split('\n');
  const elements: React.ReactNode[] = [];
  
  let inCodeBlock = false;
  let codeBlockContent: string[] = [];
  
  let listBuffer: React.ReactNode[] = [];
  let tableBuffer: string[] = [];

  const flushList = () => {
    if (listBuffer.length > 0) {
      elements.push(<ul key={`list-${elements.length}`} className="list-disc pl-6 mb-4 space-y-1 text-gray-900 dark:text-gray-300">{[...listBuffer]}</ul>);
      listBuffer = [];
    }
  };

  const flushTable = () => {
    if (tableBuffer.length > 0) {
      elements.push(renderTable(tableBuffer, `table-${elements.length}`));
      tableBuffer = [];
    }
  };

  lines.forEach((line, index) => {
    const trimmedLine = line.trim();

    // Code Blocks
    if (trimmedLine.startsWith('```')) {
      flushList();
      flushTable();
      if (inCodeBlock) {
        elements.push(
          <div key={`code-${index}`} className="my-4 bg-gray-100 dark:bg-gray-900 rounded-lg p-4 overflow-x-auto border border-gray-300 dark:border-gray-700 shadow-sm">
            <pre className="text-sm font-mono text-emerald-900 dark:text-green-400">
              {codeBlockContent.join('\n')}
            </pre>
          </div>
        );
        codeBlockContent = [];
        inCodeBlock = false;
      } else {
        inCodeBlock = true;
      }
      return;
    }

    if (inCodeBlock) {
      codeBlockContent.push(line);
      return;
    }

    // Tables
    if (trimmedLine.startsWith('|')) {
      flushList();
      tableBuffer.push(line);
      return;
    } else {
      flushTable();
    }

    // Lists
    if (trimmedLine.startsWith('- ')) {
       const text = trimmedLine.substring(2);
       listBuffer.push(<li key={`li-${index}`}>{parseInline(text)}</li>);
       return;
    } else {
        flushList();
    }

    // Headers
    if (line.startsWith('### ')) {
      elements.push(<h3 key={index} className="text-xl font-bold text-gray-900 dark:text-white mt-6 mb-3">{line.replace('### ', '')}</h3>);
    } else if (line.startsWith('## ')) {
      elements.push(<h2 key={index} className="text-2xl font-bold text-sec-red mt-8 mb-4 border-b border-gray-200 dark:border-gray-700 pb-2">{line.replace('## ', '')}</h2>);
    } else if (line.startsWith('# ')) {
      elements.push(<h1 key={index} className="text-3xl font-bold text-gray-900 dark:text-white mt-4 mb-6">{line.replace('# ', '')}</h1>);
    } 
    // Empty lines
    else if (trimmedLine === '') {
      // ignore
    } else {
      elements.push(<p key={index} className="mb-3 text-gray-900 dark:text-gray-300 leading-relaxed">{parseInline(line)}</p>);
    }
  });
   
  flushList();
  flushTable();

  return <div className="markdown-body">{elements}</div>;
};

// Helper for bold/italic/code inline
const parseInline = (text: string): React.ReactNode => {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} className="bg-gray-200 dark:bg-gray-800 text-pink-800 dark:text-yellow-300 px-1 py-0.5 rounded text-sm font-mono border border-gray-300 dark:border-gray-700">{part.slice(1, -1)}</code>;
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="text-black dark:text-white font-bold">{part.slice(2, -2)}</strong>;
    }
    return part;
  });
};

const renderTable = (rows: string[], key: string) => {
    const parseRow = (r: string) => {
        let content = r.trim();
        if (content.startsWith('|')) content = content.substring(1);
        if (content.endsWith('|')) content = content.substring(0, content.length - 1);
        return content.split('|').map(c => c.trim());
    };

    if (rows.length < 2) return null;

    const headerCols = parseRow(rows[0]);
    // rows[1] is the separator line |---|---| so skip it
    const bodyRows = rows.slice(2).map(parseRow);

    return (
        <div key={key} className="my-6 overflow-x-auto rounded-lg border border-gray-300 dark:border-gray-700 shadow-md">
            <table className="min-w-full divide-y divide-gray-300 dark:divide-gray-700 bg-white dark:bg-gray-800/40 text-left text-sm text-gray-900 dark:text-gray-300">
                <thead className="bg-gray-100 dark:bg-gray-900 font-medium text-gray-900 dark:text-white">
                    <tr>
                        {headerCols.map((h, i) => (
                            <th key={i} className="px-4 py-3 border-r border-gray-300 dark:border-gray-700 last:border-r-0 whitespace-nowrap">{h}</th>
                        ))}
                    </tr>
                </thead>
                <tbody className="divide-y divide-gray-300 dark:divide-gray-700">
                    {bodyRows.map((row, i) => (
                        <tr key={i} className="hover:bg-gray-50 dark:hover:bg-gray-800/60 transition-colors">
                            {row.map((cell, j) => (
                                <td key={j} className="px-4 py-3 border-r border-gray-300 dark:border-gray-700 last:border-r-0 whitespace-pre-wrap">
                                    {parseInline(cell)}
                                </td>
                            ))}
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};