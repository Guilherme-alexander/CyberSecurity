#!/usr/bin/env python3
"""
Script para análise de arquivos PDF em busca de indicadores de malware
Versão ajustada para reduzir falsos positivos
"""

import os
import hashlib
import re
import argparse
from pathlib import Path
from typing import Dict, List, Set
import warnings

# Suprimir warnings do pdfminer
warnings.filterwarnings("ignore")

try:
    from pdfminer.high_level import extract_text
except ImportError:
    print("❌ pdfminer.six não instalado. Execute: pip install pdfminer.six")
    exit()

class PDFAnalyzer:
    def __init__(self):
        # Padrões mais específicos para reduzir falsos positivos
        self.suspicious_patterns = [
            # JavaScript malicioso
            r'javascript:\s*eval\s*\(', 
            r'js:\s*exec\s*\(',
            r'app\.launchURL\s*\([^)]*http[^)]*\)',
            r'this\.exportDataObject\s*\(',
            
            # Comandos de shell explícitos
            r'cmd\.exe\s+/c\s+',
            r'powershell\s+-exec\s+bypass',
            r'wscript\.exe\s+[^\s]+\.(vbs|vbe)',
            r'cscript\.exe\s+[^\s]+\.(vbs|vbe)',
            
            # Executáveis e DLLs em contextos suspeitos
            r'/\w+\.exe\s+stream',
            r'/\w+\.dll\s+stream',
            r'open\s+.*\.exe',
            r'shell\s+.*\.exe',
            
            # Ofuscação avançada
            r'String\.fromCharCode\s*\([0-9,]{50,}\)',
            r'unescape\s*\([^)]{100,}\)',
            r'eval\s*\(unescape\s*\(',
            
            # Objetos PDF suspeitos
            r'/OpenAction\s+.*/JavaScript',
            r'/AA\s+.*/JavaScript',
            r'/JS\s+.*stream.*endstream',
        ]
        
        # Keywords específicas em contextos perigosos
        self.suspicious_keywords = [
            'powershell -exec bypass',
            'wscript.shell',
            'shell.execute',
            'activexobject',
            'adodb.stream',
            'scripting.filesystemobject',
            'eval(',
            'exec(',
            'runtime.exec',
            'process.start'
        ]
        
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                for pattern in self.suspicious_patterns]

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calcula hashes do arquivo"""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            print(f"Erro ao calcular hashes: {e}")
        return hashes

    def extract_text_from_pdf(self, file_path: str) -> str:
        """Extrai texto do PDF"""
        text = ""
        try:
            text = extract_text(file_path)
        except Exception as e:
            print(f"Erro ao extrair texto: {e}")
        return text

    def analyze_pdf_structure(self, file_path: str) -> Dict:
        """Analisa a estrutura do PDF"""
        analysis = {
            'javascript_detected': False,
            'embedded_files': False,
            'urls_found': [],
            'powershell_found': False,
            'vba_found': False,
            'vbs_found': False,
            'exe_found': False,
            'dll_found': False
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read().decode('latin-1', errors='ignore')
                
                # Verifica objetos JavaScript
                if '/JavaScript' in content or '/JS' in content:
                    analysis['javascript_detected'] = True
                
                # Verifica arquivos embutidos
                if '/EmbeddedFile' in content or '/EmbeddedFiles' in content:
                    analysis['embedded_files'] = True
                
                # Procura por URLs
                url_pattern = r'https?://[^\s<>"{}|\\^`[\]]+'
                analysis['urls_found'] = re.findall(url_pattern, content, re.IGNORECASE)
                
                # Verifica padrões específicos
                analysis['powershell_found'] = bool(re.search(r'powershell\s+-exec\s+bypass', content, re.IGNORECASE))
                analysis['vba_found'] = bool(re.search(r'vba\s+project', content, re.IGNORECASE))
                analysis['vbs_found'] = bool(re.search(r'\.vbs\s+stream', content, re.IGNORECASE))
                analysis['exe_found'] = bool(re.search(r'\.exe\s+stream', content, re.IGNORECASE))
                analysis['dll_found'] = bool(re.search(r'\.dll\s+stream', content, re.IGNORECASE))
                
        except Exception as e:
            print(f"Erro na análise estrutural: {e}")
        
        return analysis

    def check_suspicious_content(self, text: str) -> List[str]:
        """Verifica conteúdo suspeito no texto extraído"""
        suspicious_findings = []
        
        for pattern in self.compiled_patterns:
            matches = pattern.findall(text)
            if matches:
                suspicious_findings.extend(matches)
        
        # Verifica keywords suspeitas em contextos específicos
        for keyword in self.suspicious_keywords:
            if re.search(rf'\b{re.escape(keyword)}\b', text, re.IGNORECASE):
                suspicious_findings.append(keyword)
        
        return list(set(suspicious_findings))  # Remove duplicatas

    def analyze_pdf(self, file_path: str) -> Dict:
        """Executa análise completa do PDF"""
        if not os.path.exists(file_path):
            return {"error": "Arquivo não encontrado"}
        
        if not file_path.lower().endswith('.pdf'):
            return {"error": "O arquivo não é um PDF"}
        
        print(f"Analisando: {file_path}")
        
        results = {
            'file_info': {
                'filename': os.path.basename(file_path),
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'hashes': self.calculate_hashes(file_path)
            },
            'analysis': {}
        }
        
        # Análise estrutural
        structural_analysis = self.analyze_pdf_structure(file_path)
        results['analysis']['structural'] = structural_analysis
        
        # Extração e análise de texto
        text = self.extract_text_from_pdf(file_path)
        if text:
            # Verifica conteúdo suspeito
            suspicious_content = self.check_suspicious_content(text)
            results['analysis']['suspicious_content'] = suspicious_content
        
        return results

    def print_results(self, results: Dict):
        """Exibe apenas os indicadores solicitados"""
        if 'error' in results:
            print(f"❌ Erro: {results['error']}")
            return
        
        print("\n" + "="*50)
        print("INDICADORES DETECTADOS")
        print("="*50)
        
        structural = results['analysis']['structural']
        suspicious = results['analysis'].get('suspicious_content', [])
        
        print(f"JavaScript encontrado: {'✅ Sim' if structural['javascript_detected'] else '❌ Não'}")
        print(f"powershell encontrado: {'✅ Sim' if structural['powershell_found'] else '❌ Não'}")
        print(f"vba encontrado: {'✅ Sim' if structural['vba_found'] else '❌ Não'}")
        print(f"vbs encontrado: {'✅ Sim' if structural['vbs_found'] else '❌ Não'}")
        print(f".exe encontrado: {'✅ Sim' if structural['exe_found'] else '❌ Não'}")
        print(f".dll encontrado: {'✅ Sim' if structural['dll_found'] else '❌ Não'}")
        print(f"Arquivos embutidos: {'✅ Sim' if structural['embedded_files'] else '❌ Não'}")
        print(f"URLs encontradas: {len(structural['urls_found'])}")
        print(f"Conteúdo Suspeito encontrado: {len(suspicious)}")
        
        if suspicious:
            print("\nItens suspeitos detectados:")
            for item in suspicious[:5]:  # Mostra apenas os 5 primeiros
                print(f"  - {item}")
            if len(suspicious) > 5:
                print(f"  ... e mais {len(suspicious) - 5} itens")
        
        print("="*50)

def main():
    parser = argparse.ArgumentParser(description='Analisador de PDF para detecção de malware')
    parser.add_argument('file', help='Caminho para o arquivo PDF a ser analisado')
    
    args = parser.parse_args()
    
    analyzer = PDFAnalyzer()
    results = analyzer.analyze_pdf(args.file)
    analyzer.print_results(results)

if __name__ == "__main__":
    main()
