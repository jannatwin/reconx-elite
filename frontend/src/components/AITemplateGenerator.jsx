import { useState } from "react";
import { api } from "../api/client";

export default function AITemplateGenerator() {
  const [mode, setMode] = useState("description"); // "description" or "http"
  const [description, setDescription] = useState("");
  const [httpRequest, setHttpRequest] = useState("");
  const [httpResponse, setHttpResponse] = useState("");
  const [generatedTemplate, setGeneratedTemplate] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleGenerate = async () => {
    setIsGenerating(true);
    setError("");
    setSuccess("");
    setGeneratedTemplate("");

    try {
      let response;
      if (mode === "description") {
        response = await api.post("/templates/generate/description", { description });
      } else {
        response = await api.post("/templates/generate/http", { 
          request: httpRequest, 
          response: httpResponse || null 
        });
      }
      setGeneratedTemplate(response.data.template_yaml);
      setSuccess("Template generated successfully!");
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to generate template. Make sure AI is configured.");
    } finally {
      setIsGenerating(false);
    }
  };

  const handleSaveTemplate = async () => {
    if (!generatedTemplate) return;
    
    try {
      const name = generatedTemplate.match(/name: (.*)/)?.[1] || "AI Generated Template";
      const id = generatedTemplate.match(/id: (.*)/)?.[1] || "ai-template-" + Date.now();
      
      await api.post("/templates", {
        name,
        template_id: id,
        yaml_content: generatedTemplate
      });
      setSuccess("Template saved to library!");
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to save template.");
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedTemplate);
    setSuccess("Copied to clipboard!");
    setTimeout(() => setSuccess(""), 3000);
  };

  return (
    <div className="space-y-6">
      <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center">
          <span className="mr-2">🪄</span> AI Nuclei Template Generator
        </h3>
        <p className="text-gray-400 mb-6">
          Use AI to quickly create custom Nuclei templates from descriptions or raw HTTP traffic.
        </p>

        <div className="flex space-x-4 mb-6">
          <button
            onClick={() => setMode("description")}
            className={`px-4 py-2 rounded-md transition ${
              mode === "description" ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"
            }`}
          >
            From Description
          </button>
          <button
            onClick={() => setMode("http")}
            className={`px-4 py-2 rounded-md transition ${
              mode === "http" ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"
            }`}
          >
            From HTTP Traffic
          </button>
        </div>

        {mode === "description" ? (
          <div className="space-y-4">
            <label className="block text-sm font-medium text-gray-300">
              Vulnerability Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="e.g. Create a template to check for exposed .git directory and match 'Index of /.git'"
              className="w-full h-32 bg-gray-900 border border-gray-700 rounded-md p-3 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-300">Raw HTTP Request</label>
              <textarea
                value={httpRequest}
                onChange={(e) => setHttpRequest(e.target.value)}
                placeholder="GET /admin HTTP/1.1..."
                className="w-full h-48 bg-gray-900 border border-gray-700 rounded-md p-3 text-white font-mono text-xs"
              />
            </div>
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-300">Raw HTTP Response (Optional)</label>
              <textarea
                value={httpResponse}
                onChange={(e) => setHttpResponse(e.target.value)}
                placeholder="HTTP/1.1 200 OK..."
                className="w-full h-48 bg-gray-900 border border-gray-700 rounded-md p-3 text-white font-mono text-xs"
              />
            </div>
          </div>
        )}

        <div className="mt-6">
          <button
            onClick={handleGenerate}
            disabled={isGenerating || (mode === "description" ? !description : !httpRequest)}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-md transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
          >
            {isGenerating ? (
              <>
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Generating Template...
              </>
            ) : (
              "Generate Nuclei Template"
            )}
          </button>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-900/50 border border-red-500 rounded-md text-red-200 text-sm">
            {error}
          </div>
        )}
        {success && (
          <div className="mt-4 p-3 bg-green-900/50 border border-green-500 rounded-md text-green-200 text-sm">
            {success}
          </div>
        )}
      </div>

      {generatedTemplate && (
        <div className="bg-gray-800 p-6 rounded-lg border border-gray-700 animate-fade-in">
          <div className="flex justify-between items-center mb-4">
            <h4 className="text-lg font-medium text-white">Generated YAML Template</h4>
            <div className="flex space-x-2">
              <button
                onClick={copyToClipboard}
                className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded text-sm transition"
              >
                Copy
              </button>
              <button
                onClick={handleSaveTemplate}
                className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-sm transition"
              >
                Save to Library
              </button>
            </div>
          </div>
          <pre className="bg-black p-4 rounded-md overflow-x-auto text-green-400 font-mono text-sm border border-gray-700">
            {generatedTemplate}
          </pre>
        </div>
      )}
    </div>
  );
}
