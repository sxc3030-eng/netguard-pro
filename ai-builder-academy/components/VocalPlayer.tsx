"use client";

import { useEffect, useRef, useState } from "react";

type Props = {
  text: string;
  lang?: string;
};

export default function VocalPlayer({ text, lang = "fr-FR" }: Props) {
  const [supported, setSupported] = useState<boolean>(true);
  const [playing, setPlaying] = useState(false);
  const [paused, setPaused] = useState(false);
  const [rate, setRate] = useState(1);
  const [voices, setVoices] = useState<SpeechSynthesisVoice[]>([]);
  const [voiceURI, setVoiceURI] = useState<string>("");
  const utterRef = useRef<SpeechSynthesisUtterance | null>(null);

  useEffect(() => {
    if (typeof window === "undefined" || !("speechSynthesis" in window)) {
      setSupported(false);
      return;
    }
    const load = () => {
      const all = window.speechSynthesis.getVoices();
      const filtered = all.filter((v) => v.lang.startsWith(lang.split("-")[0]));
      setVoices(filtered.length ? filtered : all);
      const preferred =
        filtered.find((v) => /female|google|amélie|audrey|virginie/i.test(v.name)) ||
        filtered[0] ||
        all[0];
      if (preferred) setVoiceURI(preferred.voiceURI);
    };
    load();
    window.speechSynthesis.onvoiceschanged = load;
    return () => {
      window.speechSynthesis.cancel();
    };
  }, [lang]);

  function speak() {
    if (!supported) return;
    const synth = window.speechSynthesis;
    synth.cancel();
    const u = new SpeechSynthesisUtterance(text);
    u.lang = lang;
    u.rate = rate;
    const v = voices.find((x) => x.voiceURI === voiceURI);
    if (v) u.voice = v;
    u.onstart = () => {
      setPlaying(true);
      setPaused(false);
    };
    u.onend = () => {
      setPlaying(false);
      setPaused(false);
    };
    u.onerror = () => {
      setPlaying(false);
      setPaused(false);
    };
    utterRef.current = u;
    synth.speak(u);
  }

  function pause() {
    window.speechSynthesis.pause();
    setPaused(true);
  }
  function resume() {
    window.speechSynthesis.resume();
    setPaused(false);
  }
  function stop() {
    window.speechSynthesis.cancel();
    setPlaying(false);
    setPaused(false);
  }

  if (!supported) {
    return (
      <div className="text-sm text-muted bg-panel border border-border rounded-lg p-3">
        La synthèse vocale n'est pas disponible sur ce navigateur. Le texte du script est affiché plus bas.
      </div>
    );
  }

  return (
    <div className="bg-panel border border-border rounded-lg p-3 sm:p-4 flex flex-wrap items-center gap-2 sm:gap-3">
      {!playing && (
        <button
          onClick={speak}
          className="bg-accent text-bg font-medium px-4 py-2 rounded-md hover:opacity-90 active:opacity-80 transition flex items-center gap-2"
        >
          <span aria-hidden>▶</span>
          <span>Écouter la leçon</span>
        </button>
      )}
      {playing && !paused && (
        <button
          onClick={pause}
          className="bg-border text-text font-medium px-4 py-2 rounded-md hover:bg-border/80 transition"
        >
          ⏸ Pause
        </button>
      )}
      {playing && paused && (
        <button
          onClick={resume}
          className="bg-accent text-bg font-medium px-4 py-2 rounded-md hover:opacity-90 transition"
        >
          ▶ Reprendre
        </button>
      )}
      {playing && (
        <button
          onClick={stop}
          className="text-muted hover:text-text px-3 py-2 rounded-md transition"
        >
          ⏹ Stop
        </button>
      )}

      <div className="flex items-center gap-2 ml-auto">
        <label className="text-xs text-muted hidden sm:inline">Vitesse</label>
        <select
          value={rate}
          onChange={(e) => setRate(parseFloat(e.target.value))}
          className="bg-bg border border-border rounded px-2 py-1.5 text-sm"
        >
          <option value="0.8">0.8×</option>
          <option value="1">1×</option>
          <option value="1.2">1.2×</option>
          <option value="1.5">1.5×</option>
          <option value="1.8">1.8×</option>
        </select>
        {voices.length > 0 && (
          <select
            value={voiceURI}
            onChange={(e) => setVoiceURI(e.target.value)}
            className="bg-bg border border-border rounded px-2 py-1.5 text-sm max-w-[160px] truncate"
            title="Choix de la voix"
          >
            {voices.map((v) => (
              <option key={v.voiceURI} value={v.voiceURI}>
                {v.name}
              </option>
            ))}
          </select>
        )}
      </div>
    </div>
  );
}
