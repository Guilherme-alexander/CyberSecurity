#!/usr/bin/env python3
"""
PDF Meta Analyzer - Analisa metadados, extrai links e verifica no VirusTotal

python PDFScan.py PDF_FILE.pdf --vt-api <API_KEY_VIRUSTOTAL> --check-urls --output <RELATORIO.json>
"""

import os
import re
import json
import requests
import argparse
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Any
import PyPDF2
import pdfminer.high_level
from urllib.parse import urlparse
import time

class PDFMetaAnalyzer:
    def __init__(self, vt_api_key: str = None):
        self.vt_api_key = vt_api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

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

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extrai metadados do PDF usando PyPDF2"""
        metadata = {}
        try:
            with open(file_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                doc_info = pdf_reader.metadata
                
                if doc_info:
                    for key, value in doc_info.items():
                        clean_key = key.replace('/', '').strip()
                        metadata[clean_key] = str(value)
                
                # Informações adicionais
                metadata['num_pages'] = len(pdf_reader.pages)
                metadata['is_encrypted'] = pdf_reader.is_encrypted
                
        except Exception as e:
            print(f"Erro ao extrair metadados: {e}")
        
        return metadata

    def extract_text_content(self, file_path: str) -> str:
        """Extrai texto do PDF usando pdfminer"""
        text = ""
        try:
            text = pdfminer.high_level.extract_text(file_path)
        except Exception as e:
            print(f"Erro ao extrair texto: {e}")
        return text

    def extract_links_from_text(self, text: str) -> List[Dict[str, str]]:
        """Extrai links do texto do PDF"""
        links = []
        
        # Padrões para URLs
        url_patterns = [
            r'https?://[^\s<>"{}|\\^`[\]]+',
            r'www\.[^\s<>"{}|\\^`[\]]+',
            r'ftp://[^\s<>"{}|\\^`[\]]+',
        ]
        
        for pattern in url_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                url = match.group(0).strip()
                if len(url) > 10:  # Filtra URLs muito curtas
                    parsed_url = urlparse(url)
                    links.append({
                        'url': url,
                        'domain': parsed_url.netloc,
                        'type': 'text_url',
                        'context': text[max(0, match.start()-50):match.end()+50] if len(text) > match.end()+50 else 'context not available'
                    })
        
        return links

    def extract_links_from_metadata(self, metadata: Dict) -> List[Dict[str, str]]:
        """Extrai links dos metadados"""
        links = []
        
        for key, value in metadata.items():
            if value:
                url_pattern = r'https?://[^\s<>"{}|\\^`[\]]+'
                matches = re.finditer(url_pattern, str(value), re.IGNORECASE)
                
                for match in matches:
                    url = match.group(0).strip()
                    parsed_url = urlparse(url)
                    links.append({
                        'url': url,
                        'domain': parsed_url.netloc,
                        'type': 'metadata_url',
                        'source_field': key,
                        'context': value
                    })
        
        return links

    def check_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """Verifica arquivo no VirusTotal usando a hash"""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key não configurada"}
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": self.vt_api_key
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"status": "not_found", "message": "Arquivo não encontrado no VirusTotal"}
            else:
                return {"error": f"Erro HTTP {response.status_code}", "response": response.text}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Erro de conexão: {e}"}
        except json.JSONDecodeError as e:
            return {"error": f"Erro ao decodificar JSON: {e}"}

    def analyze_url_reputation(self, url: str) -> Dict[str, Any]:
        """Verifica reputação de URL no VirusTotal"""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key não configurada"}
        
        # Codifica a URL para a API
        url_id = hashlib.sha256(url.encode()).hexdigest()
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.vt_api_key}
        
        try:
            response = self.session.get(vt_url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}", "url": url}
                
        except Exception as e:
            return {"error": str(e), "url": url}

    def analyze_pdf(self, file_path: str, check_urls: bool = False) -> Dict[str, Any]:
        """Executa análise completa do PDF"""
        if not os.path.exists(file_path):
            return {"error": "Arquivo não encontrado"}
        
        print(f"🔍 Analisando: {os.path.basename(file_path)}")
        
        results = {
            'file_info': {
                'filename': os.path.basename(file_path),
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'hashes': self.calculate_hashes(file_path)
            },
            'metadata': {},
            'links': {
                'from_metadata': [],
                'from_content': [],
                'all_unique': []
            },
            'virustotal': {},
            'url_analysis': {}
        }
        
        # Extrai metadados
        print("📊 Extraindo metadados...")
        metadata = self.extract_metadata(file_path)
        results['metadata'] = metadata
        
        # Extrai texto e links
        print("🔗 Extraindo links...")
        text = self.extract_text_content(file_path)
        
        # Links dos metadados
        meta_links = self.extract_links_from_metadata(metadata)
        results['links']['from_metadata'] = meta_links
        
        # Links do conteúdo
        content_links = self.extract_links_from_text(text)
        results['links']['from_content'] = content_links
        
        # Todos os links únicos
        all_links = meta_links + content_links
        unique_links = {}
        for link in all_links:
            if link['url'] not in unique_links:
                unique_links[link['url']] = link
        results['links']['all_unique'] = list(unique_links.values())
        
        # Verificação no VirusTotal
        if self.vt_api_key:
            print("🔒 Verificando no VirusTotal...")
            vt_result = self.check_virustotal(results['file_info']['hashes']['sha256'])
            results['virustotal'] = vt_result
            
            # Análise de URLs se solicitado
            if check_urls and results['links']['all_unique']:
                print("🌐 Verificando URLs no VirusTotal...")
                results['url_analysis'] = {}
                for i, link in enumerate(results['links']['all_unique']):
                    if i < 5:  # Limita a 5 URLs para não exceder rate limit
                        print(f"   Analisando URL {i+1}/{min(5, len(results['links']['all_unique']))}...")
                        url_result = self.analyze_url_reputation(link['url'])
                        results['url_analysis'][link['url']] = url_result
                        time.sleep(1)  # Rate limiting
                    else:
                        break
        
        return results

    def print_detailed_report(self, results: Dict):
        """Exibe relatório detalhado"""
        if 'error' in results:
            print(f"❌ Erro: {results['error']}")
            return
        
        print("\n" + "="*80)
        print("📋 RELATÓRIO COMPLETO DE ANÁLISE DE PDF")
        print("="*80)
        
        # Informações do arquivo
        info = results['file_info']
        print(f"\n📄 Arquivo: {info['filename']}")
        print(f"📁 Tamanho: {info['file_size']:,} bytes")
        print(f"🔒 MD5: {info['hashes']['md5']}")
        print(f"🔒 SHA1: {info['hashes']['sha1']}")
        print(f"🔒 SHA256: {info['hashes']['sha256']}")
        
        # Metadados
        print(f"\n📊 METADADOS:")
        for key, value in results['metadata'].items():
            if key not in ['num_pages', 'is_encrypted'] and len(str(value)) < 100:
                print(f"   {key}: {value}")
        
        print(f"   Número de páginas: {results['metadata'].get('num_pages', 'N/A')}")
        print(f"   Criptografado: {results['metadata'].get('is_encrypted', 'N/A')}")
        
        # Links
        print(f"\n🔗 LINKS ENCONTRADOS:")
        print(f"   Nos metadados: {len(results['links']['from_metadata'])}")
        print(f"   No conteúdo: {len(results['links']['from_content'])}")
        print(f"   Únicos: {len(results['links']['all_unique'])}")
        
        if results['links']['all_unique']:
            print(f"\n   Lista de URLs únicas:")
            for i, link in enumerate(results['links']['all_unique'][:10]):  # Mostra até 10
                print(f"   {i+1}. {link['url']}")
                print(f"      Domínio: {link['domain']}")
                print(f"      Tipo: {link['type']}")
            
            if len(results['links']['all_unique']) > 10:
                print(f"   ... e mais {len(results['links']['all_unique']) - 10} URLs")
        
        # VirusTotal - Análise do arquivo
        if results.get('virustotal'):
            print(f"\n🔒 VIRUSTOTAL - ANÁLISE DO ARQUIVO:")
            vt = results['virustotal']
            
            if 'data' in vt and 'attributes' in vt['data']:
                attrs = vt['data']['attributes']
                stats = attrs.get('last_analysis_stats', {})
                
                print(f"   Detectado por: {stats.get('malicious', 0)} motores")
                print(f"   Limpo por: {stats.get('harmless', 0)} motores")
                print(f"   Suspeito por: {stats.get('suspicious', 0)} motores")
                print(f"   Não categorizado: {stats.get('undetected', 0)} motores")
                
                if stats.get('malicious', 0) > 0:
                    print(f"   🚨 STATUS: MALICIOSO")
                else:
                    print(f"   ✅ STATUS: LIMPO")
                    
            elif 'status' in vt and vt['status'] == 'not_found':
                print("   ℹ️  Arquivo não encontrado no VirusTotal")
            elif 'error' in vt:
                print(f"   ❌ Erro: {vt['error']}")
        
        # VirusTotal - Análise de URLs
        if results.get('url_analysis'):
            print(f"\n🌐 VIRUSTOTAL - ANÁLISE DE URLs:")
            for url, analysis in results['url_analysis'].items():
                print(f"\n   URL: {url}")
                
                if 'data' in analysis and 'attributes' in analysis['data']:
                    stats = analysis['data']['attributes'].get('last_analysis_stats', {})
                    print(f"      Detectado por: {stats.get('malicious', 0)} motores")
                    print(f"      Limpo por: {stats.get('harmless', 0)} motores")
                    
                    if stats.get('malicious', 0) > 0:
                        print(f"      🚨 STATUS: MALICIOSO")
                    else:
                        print(f"      ✅ STATUS: LIMPO")
                elif 'error' in analysis:
                    print(f"      ❌ Erro: {analysis['error']}")
        
        print("\n" + "="*80)

def main():
    parser = argparse.ArgumentParser(description='Analisador de Metadados e Links de PDF com VirusTotal')
    parser.add_argument('file', help='Caminho para o arquivo PDF')
    parser.add_argument('--vt-api', help='Chave API do VirusTotal')
    parser.add_argument('--check-urls', action='store_true', help='Verificar URLs no VirusTotal')
    parser.add_argument('--output', help='Salvar relatório em JSON')
    
    args = parser.parse_args()
    
    # Verifica se arquivo existe
    if not os.path.exists(args.file):
        print(f"❌ Arquivo não encontrado: {args.file}")
        return
    
    # Inicializa analisador
    analyzer = PDFMetaAnalyzer(vt_api_key=args.vt_api)
    
    # Executa análise
    results = analyzer.analyze_pdf(args.file, check_urls=args.check_urls)
    
    # Exibe resultados
    analyzer.print_detailed_report(results)
    
    # Salva em JSON se solicitado
    if args.output:
        output_file = args.output if args.output.endswith('.json') else args.output + '.json'
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"\n💾 Relatório salvo em: {output_file}")
        except Exception as e:
            print(f"❌ Erro ao salvar relatório: {e}")

if __name__ == "__main__":
    main()
