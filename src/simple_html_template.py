"""
Simple HTML template for Neo4j visualizer to avoid formatting issues
"""

SIMPLE_HTML_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>Security Network Analysis</title>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: #ffffff;
            min-height: 100vh;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 2.5em;
            font-weight: 700;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
            color: #ffffff;
        }}
        .header p {{
            margin: 0;
            font-size: 1.2em;
            color: #e0e0e0;
            font-weight: 500;
        }}
        .container {{
            display: flex;
            gap: 25px;
            max-width: 1400px;
            margin: 0 auto;
        }}
        .graph-container {{
            flex: 3;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .controls-panel {{
            flex: 1;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}
        .controls-panel h3 {{
            margin: 0 0 20px 0;
            font-size: 1.4em;
            font-weight: 600;
            color: #ffffff;
            border-bottom: 2px solid rgba(255, 255, 255, 0.3);
            padding-bottom: 10px;
        }}
        #network {{
            width: 100%;
            height: 600px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            background: #ffffff;
        }}
        .control-group {{
            margin-bottom: 20px;
        }}
        .control-group label {{
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            font-size: 1.1em;
            color: #ffffff;
        }}
        .control-group select {{
            width: 100%;
            padding: 10px 12px;
            border: none;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.9);
            color: #333;
            font-size: 1em;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        .control-group select:hover {{
            background: rgba(255, 255, 255, 1);
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }}
        .legend {{
            margin-top: 25px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .legend h4 {{
            margin: 0 0 15px 0;
            font-size: 1.2em;
            font-weight: 600;
            color: #ffffff;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 10px;
            padding: 5px 0;
        }}
        .legend-color {{
            width: 18px;
            height: 18px;
            margin-right: 12px;
            border-radius: 50%;
            border: 2px solid rgba(255, 255, 255, 0.5);
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }}
        .legend-item span {{
            font-size: 1em;
            font-weight: 500;
            color: #ffffff;
        }}
        .threat-alerts {{
            margin-top: 25px;
        }}
        .alert {{
            padding: 15px 18px;
            margin: 10px 0;
            border-radius: 10px;
            font-weight: 600;
            font-size: 1em;
            border: 1px solid;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }}
        .alert-critical {{
            background: rgba(244, 67, 54, 0.2);
            border-color: #f44336;
            color: #ffcdd2;
        }}
        .alert-high {{
            background: rgba(255, 152, 0, 0.2);
            border-color: #ff9800;
            color: #ffe0b2;
        }}
        .alert-success {{
            background: rgba(76, 175, 80, 0.2);
            border-color: #4caf50;
            color: #c8e6c9;
        }}
        /* Responsive design */
        @media (max-width: 1200px) {{
            .container {{
                flex-direction: column;
            }}
            .graph-container, .controls-panel {{
                flex: none;
            }}
            #network {{
                height: 500px;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Network Analysis</h1>
        <p>Analysis Time: {analysis_time} | Threats Detected: {threat_count}</p>
    </div>
    <div class="container">
        <div class="graph-container">
            <div id="network"></div>
        </div>
        <div class="controls-panel">
            <h3>🎛️ Visualization Controls</h3>
            <div class="control-group">
                <label>Graph Layout:</label>
                <select id="layout-select">
                    <option value="hierarchical">Hierarchical</option>
                    <option value="force" selected>Force-Directed</option>
                    <option value="circular">Circular</option>
                </select>
            </div>
            <div class="control-group">
                <label>Node Filter:</label>
                <select id="filter-select">
                    <option value="all">Show All</option>
                    <option value="threats">Threats Only</option>
                    <option value="hosts">Hosts Only</option>
                    <option value="services">Services Only</option>
                </select>
            </div>
            <div class="legend">
                <h4>🏷️ Node Legend</h4>
                <div class="legend-item">
                    <div class="legend-color" style="background: #4CAF50;"></div>
                    <span>Secure Hosts</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #FF9800;"></div>
                    <span>Suspicious Hosts</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #F44336;"></div>
                    <span>Compromised Hosts</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #2196F3;"></div>
                    <span>Network Services</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #9C27B0;"></div>
                    <span>Security Threats</span>
                </div>
            </div>
            <div class="threat-alerts" id="threat-alerts">{threat_alerts}</div>
        </div>
    </div>
    <script>
        const graphData = {graph_data};
        let network;
        
        function initializeGraph() {{
            const container = document.getElementById('network');
            const nodes = new vis.DataSet(graphData.nodes || []);
            const edges = new vis.DataSet(graphData.edges || []);
            const data = {{nodes: nodes, edges: edges}};
            
            const options = {{
                layout: {{
                    hierarchical: {{enabled: false}}
                }},
                physics: {{
                    enabled: true,
                    forceAtlas2Based: {{
                        gravitationalConstant: -50,
                        centralGravity: 0.01,
                        springLength: 100,
                        springConstant: 0.08,
                        damping: 0.4,
                        avoidOverlap: 0.5
                    }},
                    maxVelocity: 50,
                    minVelocity: 0.1,
                    solver: 'forceAtlas2Based',
                    stabilization: {{iterations: 150}}
                }},
                nodes: {{
                    borderWidth: 2,
                    shadow: {{
                        enabled: true,
                        color: 'rgba(0,0,0,0.3)',
                        size: 10,
                        x: 2,
                        y: 2
                    }},
                    font: {{
                        size: 14,
                        color: '#333333',
                        face: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif',
                        strokeWidth: 2,
                        strokeColor: '#ffffff'
                    }}
                }},
                edges: {{
                    width: 2,
                    shadow: {{
                        enabled: true,
                        color: 'rgba(0,0,0,0.2)',
                        size: 5,
                        x: 1,
                        y: 1
                    }},
                    smooth: {{
                        type: 'continuous'
                    }},
                    arrows: {{
                        to: {{enabled: true, scaleFactor: 1.2}}
                    }},
                    font: {{
                        size: 12,
                        color: '#666666',
                        face: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif'
                    }}
                }},
                interaction: {{
                    hover: true,
                    tooltipDelay: 200,
                    hideEdgesOnDrag: true,
                    hideNodesOnDrag: false
                }}
            }};
            
            network = new vis.Network(container, data, options);
            
            // Layout control
            document.getElementById('layout-select').addEventListener('change', function(e) {{
                const layout = e.target.value;
                let layoutOptions = {{}};
                
                switch(layout) {{
                    case 'hierarchical':
                        layoutOptions = {{
                            layout: {{hierarchical: {{enabled: true, direction: 'UD', sortMethod: 'directed'}}}},
                            physics: {{solver: 'hierarchicalRepulsion'}}
                        }};
                        break;
                    case 'force':
                        layoutOptions = {{
                            layout: {{hierarchical: {{enabled: false}}}},
                            physics: {{solver: 'forceAtlas2Based'}}
                        }};
                        break;
                    case 'circular':
                        layoutOptions = {{
                            layout: {{hierarchical: {{enabled: false}}}},
                            physics: {{enabled: false}}
                        }};
                        arrangeNodesInCircle();
                        break;
                }}
                network.setOptions(layoutOptions);
            }});
            
            // Filter control
            document.getElementById('filter-select').addEventListener('change', function(e) {{
                filterNodes(e.target.value);
            }});
        }}
        
        function arrangeNodesInCircle() {{
            const nodeIds = nodes.getIds();
            const radius = 250;
            const angleStep = (2 * Math.PI) / nodeIds.length;
            
            nodeIds.forEach((nodeId, index) => {{
                const angle = index * angleStep;
                const x = radius * Math.cos(angle);
                const y = radius * Math.sin(angle);
                
                nodes.update({{
                    id: nodeId,
                    x: x,
                    y: y,
                    fixed: {{x: true, y: true}}
                }});
            }});
        }}
        
        function filterNodes(filter) {{
            let filteredNodes = graphData.nodes || [];
            
            switch(filter) {{
                case 'threats':
                    filteredNodes = filteredNodes.filter(n => n.group === 'threat');
                    break;
                case 'hosts':
                    filteredNodes = filteredNodes.filter(n => n.group === 'host');
                    break;
                case 'services':
                    filteredNodes = filteredNodes.filter(n => n.group === 'service');
                    break;
                case 'all':
                default:
                    filteredNodes = graphData.nodes || [];
                    break;
            }}
            
            const nodes = new vis.DataSet(filteredNodes);
            
            // Filter edges to match visible nodes
            const visibleNodeIds = new Set(filteredNodes.map(n => n.id));
            const filteredEdges = (graphData.edges || []).filter(e =>
                visibleNodeIds.has(e.from) && visibleNodeIds.has(e.to)
            );
            const edges = new vis.DataSet(filteredEdges);
            
            network.setData({{nodes: nodes, edges: edges}});
        }}
        
        document.addEventListener('DOMContentLoaded', initializeGraph);
    </script>
</body>
</html>'''