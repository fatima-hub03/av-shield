from groq import Groq

try:
    from config_local import GROQ_API_KEY
except:
    GROQ_API_KEY = ""

def analyze_threat(filename, result, threat_name, heuristic_score, entropy):
    client = Groq(api_key=GROQ_API_KEY)
    
    prompt = f"""Tu es un expert en cybersécurité. Analyse ce fichier détecté par un antivirus et réponds en français.

Fichier : {filename}
Résultat : {result}
Menace détectée : {threat_name if threat_name else 'Inconnue'}
Score heuristique : {heuristic_score}/100
Entropie : {entropy}

Donne une analyse structurée avec exactement ces 5 sections :

🏷️ CLASSIFICATION
[Choisis parmi : Trojan / Backdoor / Ransomware / Keylogger / Cryptominer / Script malveillant / Spyware / Worm / Adware / Code obfusqué / Inconnu]
[Justifie en 1 phrase]

🎯 TYPE DE MENACE
[Explique le type de malware/menace en 2-3 phrases]

⚠️ POURQUOI C'EST DANGEREUX
[Explique les risques concrets en 2-3 phrases]

🛡️ RECOMMANDATIONS
[3 actions concrètes à faire]

🔴 NIVEAU DE RISQUE : [FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE]
[Justification en 1 phrase]"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=500,
        temperature=0.3
    )
    
    return response.choices[0].message.content

