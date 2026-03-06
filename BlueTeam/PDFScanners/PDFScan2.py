#!/usr/bin/env python3
"""
Analisador de PDF Corrigido - Menos Falsos Positivos
"""

import os
import re
import zlib
import hashlib
import argparse
from typing import Dict, List
import warnings
warnings.filterwarnings("ignore")

class SmartPDFAnalyzer:
    def __init__(self):
        # Padrões REAIS de malware (menos falsos positivos)
        self.real_malicious_patterns = [
            # JavaScript perigoso
            r'javascript:\s*eval\s*\(', 
            r'js:\s*exec\s*\(',
            r'app\.launchURL\s*\([^)]*http[^)]*\)',
            r'this\.exportDataObject\s*\(',
            
            # Shell commands explícitos
            r'cmd\.exe\s+/c\s+',
            r'powershell\s+-exec\s+bypass',
            r'wscript\.exe\s+[^\s]+\.vbs',
            r'/\w+\s+obj\s*<<.*/S\s+/JavaScript.*>>',
            
            # URLs maliciosas específicas
            r'http://(?:[0-9]{1,3}\.){3}[0-9]{1,3}/',
            r'http://[a-z0-9]{16,}\.(com|net|org)',
            
            # Ofuscação real
            r'String\.fromCharCode\s*\([0-9,]{50,}\)',
            r'unescape\s*\([^)]{100,}\)',
            r'eval\s*\(unescape\s*\(',
            
            # Objetos realmente suspeitos
            r'/OpenAction\s+.*/JavaScript',
            r'/AA\s+.*/JavaScript',
            r'/JS\s+.*stream.*endstream',
        ]
        
        # Whitelist de padrões legítimos
        self.whitelist_patterns = [
            r'http://ns\.adobe\.com/',
            r'http://prismstandard\.org/',
            r'http://www\.w3\.org/',
            r'http://xmlns\.com/',
            r'http://purl\.org/',
            r'startxref\s+\d+',
            r'/\w+\s+Do',
            r'/\w+\s+PDF',
            r'/%PDF',
            r'/PageLayout',
            r'/ViewerPreferences',
        ]
        
        self.malicious_regex = [re.compile(p, re.IGNORECASE) 
                              for p in self.real_malicious_patterns]
        self.whitelist_regex = [re.compile(p, re.IGNORECASE) 
                              for p in self.whitelist_patterns]

    def is_whitelisted(self, content: str) -> bool:
        """Verifica se é conteúdo legítimo"""
        for pattern in self.whitelist_regex:
            if pattern.search(content):
                return True
        return False

    def analyze_pdf(self, file_path: str) -> Dict:
        """Análise inteligente com whitelist"""
        if not os.path.exists(file_path):
            return {"error": "Arquivo não encontrado"}
        
        print(f"🔍 Analisando: {os.path.basename(file_path)}")
        
        results = {
            'file_info': {
                'filename': os.path.basename(file_path),
                'size': os.path.getsize(file_path),
                'hashes': self.calculate_hashes(file_path)
            },
            'findings': {
                'javascript_detected': False,
                'embedded_files': False,
                'suspicious_urls': [],
                'real_threats': [],
                'whitelisted_content': []
            },
            'verdict': 'CLEAN'
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read().decode('latin-1', errors='ignore')
                
                # Verifica JavaScript
                if '/JavaScript' in content or '/JS' in content:
                    results['findings']['javascript_detected'] = True
                
                # Verifica arquivos embutidos
                if '/EmbeddedFile' in content:
                    results['findings']['embedded_files'] = True
                
                # Análise inteligente
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line or len(line) < 10:
                        continue
                    
                    # Pula conteúdo whitelisted
                    if self.is_whitelisted(line):
                        results['findings']['whitelisted_content'].append(line[:100])
                        continue
                    
                    # Verifica ameaças reais
                    for pattern in self.malicious_regex:
                        if pattern.search(line):
                            threat = pattern.pattern[:50] + "..."
                            if threat not in results['findings']['real_threats']:
                                results['findings']['real_threats'].append(threat)
                
                # Determina veredito
                if (results['findings']['javascript_detected'] or 
                    results['findings']['embedded_files'] or
                    results['findings']['real_threats']):
                    results['verdict'] = 'SUSPICIOUS'
                else:
                    results['verdict'] = 'CLEAN'
                    
        except Exception as e:
            results['error'] = str(e)
            
        return results

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calcula hashes do arquivo"""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except:
            pass
        return hashes

    def print_results(self, results: Dict):
        """Exibe resultados simplificados"""
        print("\n" + "="*50)
        print("📊 RESULTADOS DA ANÁLISE INTELIGENTE")
        print("="*50)
        
        if 'error' in results:
            print(f"❌ Erro: {results['error']}")
            return
        
        print(f"📄 Arquivo: {results['file_info']['filename']}")
        print(f"📁 Tamanho: {results['file_info']['size']:,} bytes")
        print(f"🔒 MD5: {results['file_info']['hashes']['md5']}")
        
        print(f"\n🔍 Achados:")
        print(f"   JavaScript: {'✅' if results['findings']['javascript_detected'] else '❌'}")
        print(f"   Arquivos embutidos: {'✅' if results['findings']['embedded_files'] else '❌'}")
        print(f"   Ameaças reais: {len(results['findings']['real_threats'])}")
        print(f"   Conteúdo legítimo: {len(results['findings']['whitelisted_content'])}")
        
        if results['findings']['real_threats']:
            print(f"\n⚠️  Ameaças detectadas:")
            for threat in results['findings']['real_threats'][:3]:
                print(f"   • {threat}")
        
        print(f"\n🎯 Veredito: {results['verdict']}")
        
        if results['verdict'] == 'CLEAN':
            print("✅ Arquivo parece seguro (combinando com antivírus)")
        else:
            print("⚠️  Recomendação: Analisar com ferramentas especializadas")
        
        print("="*50)

def main():
    parser = argparse.ArgumentParser(description='Analisador Inteligente de PDF')
    parser.add_argument('file', help='Arquivo PDF para análise')
    args = parser.parse_args()
    
    analyzer = SmartPDFAnalyzer()
    results = analyzer.analyze_pdf(args.file)
    analyzer.print_results(results)

if __name__ == "__main__":
    main()
