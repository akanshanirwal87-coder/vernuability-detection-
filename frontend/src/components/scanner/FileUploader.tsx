import React, { useState, useRef } from 'react';
import { Upload, FileCode, CheckCircle2, AlertCircle } from 'lucide-react';

interface FileUploaderProps {
  onFileLoaded: (file: File, content: string) => void;
  acceptedExtensions?: string[];
}

export const FileUploader: React.FC<FileUploaderProps> = ({
  onFileLoaded,
  acceptedExtensions = ['.py', '.js', '.ts', '.jsx', '.tsx', '.json', '.toml', '.txt'],
}) => {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const processFile = (file: File) => {
    setError(null);
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!acceptedExtensions.includes(ext)) {
      setError(`Unsupported file extension ${ext}. Supported: ${acceptedExtensions.join(', ')}`);
      return;
    }

    if (file.size > 2 * 1024 * 1024) {
      setError('File size exceeds 2MB limit.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setSelectedFile(file);
      onFileLoaded(file, content);
    };
    reader.onerror = () => {
      setError('Failed to read file from disk.');
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="space-y-3">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`flex flex-col items-center justify-center rounded-2xl border-2 border-dashed p-8 text-center cursor-pointer transition-all ${
          dragOver
            ? 'border-indigo-400 bg-indigo-950/20'
            : 'border-slate-800 bg-[#111827]/70 hover:border-slate-700 hover:bg-[#111827]'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept={acceptedExtensions.join(',')}
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              processFile(e.target.files[0]);
            }
          }}
        />

        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 mb-3">
          <Upload className="h-6 w-6" />
        </div>

        <p className="text-sm font-semibold text-white">
          Click to upload or drag and drop source file
        </p>
        <p className="text-xs text-slate-400 mt-1">
          Supports Python (.py), JavaScript (.js), TypeScript (.ts), dependencies (.txt, .json, .toml)
        </p>

        {selectedFile && (
          <div className="mt-4 flex items-center gap-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 text-xs text-emerald-400">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span className="font-mono font-medium">{selectedFile.name}</span>
            <span className="text-[10px] text-emerald-500">
              ({(selectedFile.size / 1024).toFixed(1)} KB)
            </span>
          </div>
        )}
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
};

export default FileUploader;
