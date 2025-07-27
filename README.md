# 🔍 Explainable PCAP Analyzer with LightRAG

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![LightRAG](https://img.shields.io/badge/LightRAG-0.1.2-orange.svg)](https://github.com/HKUDS/LightRAG)

Advanced network security analysis tool with AI-powered threat detection and interactive knowledge graphs using LightRAG framework.

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Interface │────│  PCAP Processor  │────│ Knowledge Graph │
│   (Streamlit)   │    │   (Advanced)     │    │ (LightRAG+Neo4j)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         │              ┌──────────────────┐              │
         └──────────────│  Visualization   │──────────────┘
                        │    Engine        │
                        └──────────────────┘
```

## ✨ Features

### 🔄 Knowledge Graph & RAG Integration

#### **LightRAG Framework Integration**
- **Graph-Augmented Generation**: Unlike traditional RAG that treats documents as isolated chunks, LightRAG builds a comprehensive knowledge graph that captures entities and their relationships
- **Multi-hop Reasoning**: Enables complex queries that require traversing multiple relationships in the network security data
- **Hybrid Query Modes**: Supports naive, local, global, and hybrid query modes for different analysis needs

#### **Entity Extraction Process**
```
Raw PCAP Data → Security Analysis → Entity Recognition → Relationship Mapping
      ↓                ↓                    ↓                    ↓
Network Traffic → Threats/Vulnerabilities → Hosts/Services → Attack Vectors
      ↓                ↓                    ↓                    ↓
Knowledge Documents ← Entity Relationships ← Graph Construction ← Neo4j Storage
```

### 🧠 AI-Powered Analysis
- **OpenAI GPT-4 Security Assessment**: Advanced threat detection using large language models
- **Natural Language Query Interface**: Ask questions about your network in plain English
- **Behavioral Pattern Recognition**: Identify anomalous network behavior
- **Automated Risk Scoring**: Quantitative security assessment

### 🕸️ Knowledge Graph Features
- **LightRAG + Neo4j Integration**: Powerful graph database backend
- **Interactive Network Visualizations**: Explore network relationships visually
- **Relationship Mapping**: Understand connections between network entities
- **Query Network Intelligence**: Advanced graph-based queries

### 📊 Comprehensive Reporting
- **Executive Security Summaries**: High-level reports for management
- **Detailed Technical Reports**: In-depth analysis for security teams
- **Interactive Dashboards**: Real-time security monitoring
- **Multiple Export Formats**: JSON, HTML, PNG, SVG support

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **OpenAI API Key** (for AI-powered analysis)
- **Neo4j Database** (optional but recommended for knowledge graphs)
- **Docker** (recommended for easy deployment)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/abyasham/xplainable-pcap-analyzer-lightrag.git
   cd xplainable-pcap-analyzer-lightrag
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and configuration
   ```

4. **Configure the application**
   ```bash
   # Edit config/config.yaml as needed
   ```

### Docker Setup (Recommended)

```bash
# Build and run with Docker Compose
docker-compose up -d

# The web interface will be available at http://localhost:8501
```

## 📖 Usage

### Command Line Interface

#### Analyze a PCAP file
```bash
python main.py analyze path/to/your/file.pcap --output results/
```

#### Run the web interface
```bash
python main.py web --host localhost --port 8501
```

#### Query the knowledge graph
```bash
python main.py query "Show me all suspicious network connections" --mode hybrid
```

### Web Interface

1. Start the web interface:
   ```bash
   streamlit run src/web_interface.py
   ```

2. Open your browser to `http://localhost:8501`

3. Upload a PCAP file and start analyzing!

### Query Modes & Capabilities

**LightRAG Query Modes**:

- **Naive Mode**: Simple keyword matching against security documents
- **Local Mode**: Focus on specific entities and their immediate relationships
- **Global Mode**: Broader context analysis across the entire network knowledge graph  
- **Hybrid Mode**: ⭐ **Optimal for Security Analysis** - Combines all approaches for comprehensive threat intelligence

**Advanced Security Queries Supported**:
```sql
-- Examples of complex security reasoning enabled by the knowledge graph:

"Show me the attack path from external threats to internal databases"
→ Traverses: External_IP → Compromised_Host → Lateral_Movement → Database_Server

"What vulnerabilities exist in services accessible from the internet?"  
→ Joins: Internet_Accessible_Services + Vulnerability_Database + Exploit_Likelihood

"Identify all hosts that communicate with known malicious domains"
→ Correlates: DNS_Queries + Threat_Intelligence + Host_Communications

"Map the blast radius if host X is compromised"
→ Analyzes: Host_Relationships + Service_Dependencies + Trust_Boundaries
```

## 📁 Project Structure

```
xplainable-pcap-analyzer-lightrag/
├── main.py                    # Main application entry point
├── requirements.txt           # Python dependencies
├── docker-compose.yml         # Docker configuration
├── Dockerfile                 # Docker image definition
├── .env.example              # Environment variables template
├── .gitignore                # Git ignore rules
├── config/
│   └── config.yaml           # Application configuration
├── src/
│   ├── pcap_processor.py     # Enhanced PCAP processing
│   ├── security_analyzer.py  # Advanced security analysis
│   ├── knowledge_graph.py    # LightRAG + Neo4j integration
│   ├── visualization.py      # Interactive visualizations
│   └── web_interface.py      # Streamlit web interface
├── data/
│   └── pcaps/               # PCAP files storage
├── output/
│   ├── reports/             # Analysis reports
│   ├── graphs/              # Knowledge graphs
│   └── visualizations/      # Charts and plots
└── README.md
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```bash
# OpenAI API Configuration
OPENAI_API_KEY=your_openai_api_key_here

# Neo4j Database Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_neo4j_password_here

# Optional: Jina Reranker API
JINA_API_KEY=your_jina_api_key_here

# Application Settings
LOG_LEVEL=INFO
DEBUG_MODE=false
```

### Configuration File

Edit [`config/config.yaml`](config/config.yaml) to customize:

- **OpenAI models and parameters**
- **Neo4j connection settings**
- **LightRAG configuration**
- **Security analysis options**
- **Visualization preferences**

## 🛠️ Development

### Setting up Development Environment

```bash
# Clone the repository
git clone https://github.com/abyasham/xplainable-pcap-analyzer-lightrag.git
cd xplainable-pcap-analyzer-lightrag

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

### Running Tests

```bash
# Run unit tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src/
```

## 📊 Example Analysis Results

### Security Dashboard
- **Risk Score**: Quantitative security assessment
- **Threat Detection**: AI-powered threat identification
- **Network Topology**: Interactive network visualization
- **Attack Timeline**: Chronological security events

### Knowledge Graph Queries
```python
# Example queries you can run:
"What are the most vulnerable services in my network?"
"Show me all communication with external IP addresses"
"Identify potential data exfiltration attempts"
"Map the network topology and trust relationships"
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[LightRAG](https://github.com/HKUDS/LightRAG)**: For the powerful graph-augmented generation framework
- **[Neo4j](https://neo4j.com/)**: For the graph database backend
- **[OpenAI](https://openai.com/)**: For the AI-powered analysis capabilities
- **[Streamlit](https://streamlit.io/)**: For the web interface framework

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/abyasham/xplainable-pcap-analyzer-lightrag/issues)
- **Discussions**: [GitHub Discussions](https://github.com/abyasham/xplainable-pcap-analyzer-lightrag/discussions)
- **Email**: [your-email@example.com](mailto:your-email@example.com)

## 🔮 Roadmap

- [ ] **Real-time PCAP Analysis**: Live network monitoring
- [ ] **Machine Learning Models**: Custom threat detection models
- [ ] **API Integration**: RESTful API for programmatic access
- [ ] **Multi-format Support**: Support for more network capture formats
- [ ] **Cloud Deployment**: AWS/Azure deployment templates
- [ ] **Advanced Visualizations**: 3D network graphs and VR support

---

**Made with ❤️ for the cybersecurity community**
