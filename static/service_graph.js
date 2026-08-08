

document.addEventListener("DOMContentLoaded", function () {

    const container = document.getElementById("policyGraph");

    if (!container) {
        console.error("policyGraph container not found");
        return;
    }

    if (typeof cytoscape === "undefined") {
        console.error("Cytoscape is not loaded");
        container.innerHTML =
            "<div style='color:#DC3545;padding:20px;'>Cytoscape failed to load.</div>";
        return;
    }

    const graphData = document.getElementById("graph-data");

    if (!graphData) {
        console.error("graph-data element not found");
        container.innerHTML =
            "<div style='color:#FFC107;padding:20px;'>No graph data found.</div>";
        return;
    }

    let elements = [];

    try {
        elements = JSON.parse(graphData.textContent);

    } catch (error) {
        console.error("Failed to parse graph JSON", error);
        container.innerHTML =
            "<div style='color:#DC3545;padding:20px;'>Failed to parse graph data.</div>";
        return;
    }

    if (!elements || elements.length === 0) {
        console.error("No graph elements available");
        container.innerHTML =
            "<div style='color:#FFC107;padding:20px;'>No graph elements available for this service.</div>";
        return;
    }

    let layoutName = "breadthfirst";

    if (typeof cytoscapeDagre !== "undefined") {
        cytoscape.use(cytoscapeDagre);
        layoutName = "dagre";
    } else {
        console.warn("Dagre not available. Falling back to breadthfirst layout.");
    }

    window.cy = cytoscape({
        container: container,

        elements: elements,
        wheelSensitivity: 0.12,
        minZoom: 0.25,
        maxZoom: 2.5,

        style: [
            {
                selector: "node",
                style: {
                    "label": "data(label)",
                    "text-wrap": "wrap",
                    "text-max-width": 230,
                    "text-valign": "center",
                    "text-halign": "center",
                    "font-size": "24px",
                    "font-weight": "600",
                    "color": "#E2E8F0",
                    "background-color": "#334155",
                    "border-width": 2,
                    "border-color": "#64748B",
                    "width": 280,
                    "height": 160,
                    "shape": "round-rectangle",
                    "padding": "10px"
                }
            },

            {
                selector: "node[type='service']",
                style: {
                    "background-color": "#01A982",
                    "border-color": "#7FFFD4",
                    "color": "#001B14",

                    "shadow-blur": 40,
                    "shadow-opacity": 1,
                    "shadow-color": "#01A982",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0
                }
            },

            {
                selector: "node[type='group']",
                style: {
                    "background-color": "#1F2937",
                    "border-color": "#6B7280",

                    "shadow-blur": 40,
                    "shadow-opacity": 1,
                    "shadow-color": "#01A982",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0,
                    "width": 200,
                    "height": 100
                }
            },

            {
                selector: "node[type='authentication']",
                style: {
                    "width": 200,
                    "height": 100,
                    "padding": "8px",
                    "font-size": "20px",
                    "text-max-width": 180
                }
            },

            {
                selector: "node[type='authorisation']",
                style: {
                    "width": 200,
                    "height": 100,
                    "padding": "8px",
                    "font-size": "20px",
                    "text-max-width": 180
                }
            },

            {
                selector: "node[type='auth_method']",
                style: {
                    "background-color": "#2563EB",
                    "border-color": "#93C5FD",

                    "shadow-blur": 40,
                    "shadow-opacity": 1,
                    "shadow-color": "#01A982",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0,
                    "width": "label",
                    "height": "label",
                    "padding": "20px",
                    "text-wrap": "wrap",
                    "text-max-width": 240,
                }
            },

            {
                selector: "node[type='auth_source']",
                style: {
                    "background-color": "#0D6EFD",
                    "border-color": "#93C5FD",

                    "shadow-blur": 40,
                    "shadow-opacity": 1,
                    "shadow-color": "#01A982",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0,
                    "width": "label",
                    "height": "label",
                    "padding": "20px",
                    "text-wrap": "wrap",
                    "text-max-width": 240,
                }
            },

            {
                selector: "node[type='authz_source']",
                style: {
                    "background-color": "#7C3AED",
                    "border-color": "#C4B5FD",

                    "shadow-blur": 40,
                    "shadow-opacity": 1,
                    "shadow-color": "#01A982",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0,
                    "width": "label",
                    "height": "label",
                    "padding": "20px",
                    "text-wrap": "wrap",
                    "text-max-width": 240,
                }
            },

            {
                selector: "node[type='role_mapping']",
                style: {
                    "background-color": "#06B6D4",
                    "border-color": "#A5F3FC",
                    "color": "#042F2E",

                    "width": "label",
                    "height": "label",

                    "padding": "25px",

                    "text-wrap": "wrap",
                    "text-max-width": 240,

                    "shadow-blur": 40,
                    "shadow-opacity": 1,
                    "shadow-color": "#01A982",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0
                }
            },

            {
                selector: "node[type='role_mapping_condition'][match_type='AND']",
                style: {
                    "background-color": "#0F766E",
                    "border-color": "#5EEAD4",
                    "shadow-color": "#14B8A6"
                }
            },

            {
                selector: "node[type='role_mapping_condition'][match_type='OR']",
                style: {
                    "background-color": "#7C3AED",
                    "border-color": "#C4B5FD",
                    "shadow-color": "#A78BFA"
                }
            },

            {
                selector: "node[type='role_mapping_condition']",
                style: {
                    "background-color": "#074c5e",
                    "border-color": "#67E8F9",
                    "color": "#FFFFFF",

                    "width": "label",
                    "height": "label",

                    "padding": "20px",

                    "text-wrap": "wrap",
                    "text-max-width": 600,

                    "shadow-blur": 35,
                    "shadow-opacity": 0.9,
                    "shadow-color": "#0891B2",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0
                }
            },

            {
                selector: "node[type='mapped_role']",
                style: {
                    "background-color": "#22C55E",
                    "border-color": "#BBF7D0",
                    "color": "#052E16",

                    "width": "label",
                    "height": "label",

                    "padding": "25px",

                    "text-wrap": "wrap",
                    "text-max-width": 280,

                    "shadow-blur": 35,
                    "shadow-opacity": 0.9,
                    "shadow-color": "#22C55E",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0
                }
            },

            {
                selector: "node[type='enforcement_policy']",
                style: {
                    "background-color": "#f89148",
                    "border-color": "#FDBA74",
                    "color": "#111827",

                    "width": "label",
                    "height": "label",

                    "padding": "25px",

                    "text-wrap": "wrap",
                    "text-max-width": 240,

                    "shadow-blur": 40,
                    "shadow-opacity": 1,
                    "shadow-color": "#01A982",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0
                }
            },
            
            {
                selector: "node[type='enforcement_condition']",
                style: {
                    "background-color": "#a5415a",
                    "border-color": "#FDA4AF",
                    "color": "#FFFFFF",

                    "width": "label",
                    "height": "label",
                    "padding": "20px",
                    "text-max-width": 500,

                    "shadow-blur": 40,
                    "shadow-opacity": 1,
                    "shadow-color": "#BE123C",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0
                }
            },

            {
                selector: "node[type='enforcement_profile']",
                style: {
                    "background-color": "#e4b911",
                    "border-color": "#FEF08A",
                    "color": "#111827",

                    "width": "label",
                    "height": "label",

                    "padding": "25px",

                    "text-wrap": "wrap",
                    "text-max-width": 280,

                    "shadow-blur": 40,
                    "shadow-opacity": 1,
                    "shadow-color": "#FACC15",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0
                }
            },


            {
                selector: "node[type='enforcement_attribute']",
                style: {
                    "background-color": "#475569",
                    "border-color": "#CBD5E1",
                    "color": "#FFFFFF",

                    "width": "label",
                    "height": "label",

                    "padding": "18px",

                    "text-wrap": "wrap",
                    "text-max-width": 250,

                    "shadow-blur": 20,
                    "shadow-opacity": 0.7,
                    "shadow-color": "#CBD5E1",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0
                }
            },


            {
                selector: ".search-match",
                style: {
                    "border-width": 6,
                    "border-color": "#FFFFFF",

                    "shadow-blur": 50,
                    "shadow-opacity": 1,
                    "shadow-color": "#FFFFFF",

                    "z-index": 9999
                }
            },

            {
                selector: ".active-search-match",
                style: {

                    "border-width": 10,
                    "border-color": "#a97c01",

                    "shadow-blur": 80,
                    "shadow-opacity": 1,
                    "shadow-color": "#a97c01",

                    "z-index": 10000
                }
            },

            {
                selector: "edge.search-match",
                style: {
                    "line-color": "#FFFFFF",
                    "target-arrow-color": "#FFFFFF",
                    "width": 10
                }
            },

            {
                selector: "edge",
                style: {
                    "width": 5,
                    "line-color": "#01A982",
                    "target-arrow-color": "#01A982",
                    "target-arrow-shape": "triangle",
                    "curve-style": "unbundled-bezier",
                    "control-point-distances": 100,
                    "control-point-weights": 0.5
                }
            }
        ]
    });

    function isExpandableNode(node) {

        return (
            node.data("type") === "role_mapping" ||
            node.data("type") === "role_mapping_condition" ||
            node.data("type") === "enforcement_policy" ||
            node.data("type") === "enforcement_condition"
        );

}


function updateNodeLabel(node) {

    if (!isExpandableNode(node)) {
        return;
    }

    if (!node.data("baseLabel")) {
        node.data("baseLabel", node.data("label"));
    }

    if (node.data("collapsed") === true) {

        node.data(
            "label",
            "▶ " + node.data("baseLabel")
        );

    } else {

        node.data(
            "label",
            "▼ " + node.data("baseLabel")
        );

    }

}


function hideBranch(node) {

    node.outgoers("edge").forEach(function(edge) {

        const target =
            edge.target();

        if (target.data("parent_branch") !== node.id()) {
            return;
        }

        edge.hide();

        target.hide();

        hideBranch(target);

    });

}


function showDirectChildren(node) {

    node.outgoers("edge").forEach(function(edge) {

        const target =
            edge.target();

        if (target.data("parent_branch") !== node.id()) {
            return;
        }

        edge.show();

        target.show();

        if (target.data("collapsed") === true) {

            hideBranch(target);

        } else {

            showDirectChildren(target);

        }

        updateNodeLabel(target);

    });

}

function expandParents(node) {

    let current = node;

    while (
        current &&
        current.data("parent_branch")
    ) {

        const parent =
            window.cy.getElementById(
                current.data(
                    "parent_branch"
                )
            );

        if (
            parent &&
            parent.data(
                "collapsed"
            ) === true
        ) {

            toggleBranch(
                parent
            );

        }

        current = parent;

    }

}

function toggleBranch(node) {

    if (!isExpandableNode(node)) {
        return;
    }

    const currentlyCollapsed =
        node.data("collapsed") === true;

    if (currentlyCollapsed) {

        node.data("collapsed", false);

        showDirectChildren(node);

    } else {

        node.data("collapsed", true);

        hideBranch(node);

    }

    updateNodeLabel(node);

    const currentZoom =
        window.cy.zoom();

    const currentPan =
        window.cy.pan();

    const relayout =
        window.cy.elements(":visible").layout({
            ...layoutOptions,
            fit: false
        });

    relayout.run();

    window.cy.zoom(currentZoom);
    window.cy.pan(currentPan);

}


function initialiseCollapsedBranches() {

    window.cy.nodes().forEach(function(node) {

        updateNodeLabel(node);

        if (node.data("collapsed") === true) {
            hideBranch(node);
        }

    });

}

function resetCollapsedBranches() {

    window.cy.nodes().forEach(function(node) {

        if (isExpandableNode(node)) {

            node.data(
                "collapsed",
                true
            );

            updateNodeLabel(
                node
            );

        }

    });

    window.cy.nodes().forEach(function(node) {

        if (
            node.data("collapsed") === true
        ) {

            hideBranch(
                node
            );

        }

    });

}


    window.cy.on('mouseover', 'node', function(evt) {

        evt.target.style({
            'border-width': 6,
            'border-color': '#7FFFD4'
        });

    });

    window.cy.on('mouseout', 'node', function(evt) {

        if (evt.target === selectedNode) {
            return;
        }

        evt.target.style({
            'border-width': 2
        });

    });

    window.cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        const data = node.data();      

        if (selectedNode) {

            selectedNode.style({
                'border-width': 2
            });

        }

        node.style({
            'border-width': 8,
            'border-color': '#eaf39b'
        });

        selectedNode = node;
        if (isExpandableNode(node)) {
            toggleBranch(node);
        }

        const infoPanel =
            document.getElementById(
                "nodeInfoContent"
            );

        let nodeType = data.type;

        const typeMap = {
            "service": "Service",
            "group": "Group",
            "auth_method": "Authentication Method",
            "auth_source": "Authentication Source",
            "authz_source": "Authorisation Source",
            "role_mapping": "Role Mapping Policy",
            "role_mapping_condition": "Role Mapping Rule Condition",
            "mapped_role": "Mapped Role",
            "enforcement_policy": "Enforcement Policy",
            "enforcement_condition": "Enforcement Policy Rule Condition",
            "enforcement_profile": "Enforcement Profile",
            "enforcement_attribute": "Enforcement Attribute"
        };

        nodeType =
            typeMap[nodeType] || nodeType;

        let extraDetails = "";

        if (data.type === "service") {

            extraDetails += `
                <div class="node-info-label">
                    Service Summary
                </div>

                <div class="node-info-value">
                    Authentication Methods
                    <span style="
                        float:right;
                        color:#01A982;
                        font-weight:700;
                    ">
                        ${data.auth_method_count || 0}
                    </span>
                </div>

                <div class="node-info-value">
                    Authentication Sources
                    <span style="
                        float:right;
                        color:#01A982;
                        font-weight:700;
                    ">
                        ${data.auth_source_count || 0}
                    </span>
                </div>

                <div class="node-info-value">
                    Authorisation Sources
                    <span style="
                        float:right;
                        color:#01A982;
                        font-weight:700;
                    ">
                        ${data.authz_source_count || 0}
                    </span>
                </div>

                <div style="
                    border-top:1px solid #334155;
                    margin:8px 0;
                "></div>

                <div class="node-info-value">
                    Role Mapping Rules
                    <span style="
                        float:right;
                        color:#FACC15;
                        font-weight:700;
                    ">
                        ${data.role_rule_count || 0}
                    </span>
                </div>

                <div class="node-info-value">
                    Enforcement Rules
                    <span style="
                        float:right;
                        color:#FACC15;
                        font-weight:700;
                    ">
                        ${data.enforcement_rule_count || 0}
                    </span>
                </div>

                <div class="node-info-value">
                    Enforcement Profiles
                    <span style="
                        float:right;
                        color:#FACC15;
                        font-weight:700;
                    ">
                        ${data.enforcement_profile_count || 0}
                    </span>
                </div>
            `;
        } 
        
        if (data.role_name) {

            extraDetails += `
                <div class="node-info-label">
                    Role
                </div>

                <div class="node-info-value">
                    ${data.role_name}
                </div>
            `;
        }

        const evaluationAlgorithm =
            data.rule_combine_algo ||
            data.rule_eval_algo;

        if (evaluationAlgorithm) {

            let algorithm =
                evaluationAlgorithm;

            if (algorithm === "evaluate-all") {
                algorithm = "All Match";
            }

            if (
                algorithm === "evaluate-first" ||
                algorithm === "evaluate-first-match"
            ) {
                algorithm = "First Match";
            }

            extraDetails += `
                <div class="node-info-label">
                    Rules Evaluation Algorithm
                </div>

                <div class="node-info-value">
                    ${algorithm}
                </div>
            `;
        }

        if (
            data.type === "role_mapping" &&
            data.service_reference_count !== undefined
        ) {

            extraDetails += `
                <div class="node-info-label">
                    Usage Summary
                </div>

                <div class="node-info-value">
                    Other Services
                    <span style="
                        float:right;
                        color:#01A982;
                        font-weight:700;
                    ">
                        ${data.service_reference_count}
                    </span>
                </div>
            `;
        }

        if (data.default_role) {

            extraDetails += `
                <div class="node-info-label">
                    Default Role
                </div>

                <div class="node-info-value">
                    ${data.default_role}
                </div>
            `;
        }

        if (data.default_profile) {

            extraDetails += `
                <div class="node-info-label">
                    Default Profile
                </div>

                <div class="node-info-value">
                    ${data.default_profile}
                </div>
            `;
        }

        if (data.rule_count !== undefined) {

            extraDetails += `
                <div class="node-info-label">
                    Rules
                </div>

                <div class="node-info-value">
                    ${data.rule_count}
                </div>
            `;
        }

        if (data.match_type) {

            const matchColour =
                data.match_type === "AND"
                    ? "#855ff7"
                    : "#A78BFA";

            extraDetails += `
                <div class="node-info-label">
                    Match Type
                </div>

                <div class="node-info-value"
                    style="
                        color:${matchColour};
                        font-weight:700;
                        font-size:1rem;
                    ">
                    ${data.match_type}
                </div>
            `;
        }

        if (
            data.attributes &&
            data.attributes.length > 0
        ) {

            extraDetails += `
                <div class="node-info-label">
                    Conditions
                </div>
            `;

            data.attributes.forEach(function(attr, index) {

                let line =
                    `${attr.source_type}:${attr.attribute_name}`;

                if (
                    attr.operator &&
                    attr.operator !== "EXISTS" &&
                    attr.operator !== "NOT EXISTS"
                ) {

                    line +=
                        ` ${attr.operator} ${attr.value}`;

                } else {

                    line +=
                        ` ${attr.operator}`;

                }

                extraDetails += `
                    <div class="node-info-value"
                        style="
                            margin-bottom:4px;
                            color:#E2E8F0;
                        ">
                        ${line}
                    </div>
                `;

                if (
                    attr.endpoint_count !== null &&
                    attr.endpoint_count !== undefined
                ) {
                    
                    const exploreUrl =
                        `/repository-search?` +
                        `source_type=${encodeURIComponent(attr.source_type || "")}` +
                        `&attribute_name=${encodeURIComponent(attr.attribute_name || "")}` +
                        `&operator=${encodeURIComponent(attr.operator || "")}` +
                        `&value=${encodeURIComponent(attr.value || "")}`;

                    extraDetails += `
                        <div
                            style="
                                margin-left:20px;
                                margin-bottom:8px;
                                color:#FACC15;
                                font-size:0.85rem;
                                font-weight:600;
                            ">
                            └► ${attr.match_count_label || "Matching Endpoints"}:
                            ${attr.endpoint_count}

                            <a href=${exploreUrl} target="_blank">
                                🔎
                            </a>
                        </div>
                    `;

                }

                if (
                    index <
                    data.attributes.length - 1
                ) {

                    extraDetails += `
                        <div
                            style="
                                color:#01A982;
                                font-weight:700;
                                margin-bottom:8px;
                                margin-left:12px;
                            ">
                            ${data.match_type}
                        </div>
                    `;

                }
                
            });
            
            if (
                data.rule_match_count === null
            ) {

                extraDetails += `
                    <div class="node-info-label">
                        Rule Match Summary
                    </div>

                    <div
                        style="
                            margin-left:20px;
                            margin-bottom:8px;
                            color:#9CA3AF;
                            font-size:0.9rem;
                            font-style:italic;
                        ">
                        Not available for non-endpoint conditions
                    </div>
                `;
            }
            else if (
                data.rule_match_count !== undefined
            ) {

                extraDetails += `
                    <div class="node-info-label">
                        Rule Match Summary
                    </div>

                    <div
                        style="
                            margin-left:20px;
                            margin-bottom:8px;
                            color:#7FFFD4;
                            font-size:0.95rem;
                            font-weight:700;
                        ">
                        └► ${data.rule_match_label || "Matching Rule Endpoints"}:
                        ${data.rule_match_count}
                    </div>
                `;
            }

        }     

        if (data.profile_count !== undefined) {

            extraDetails += `
                <div class="node-info-label">
                    Profiles Applied
                </div>

                <div class="node-info-value">
                    ${data.profile_count}
                </div>
            `;
        }

        if (
            data.profile_names &&
            data.profile_names.length > 0
        ) {

            extraDetails += `
                <div class="node-info-label">
                    Profiles
                </div>
            `;

            data.profile_names.forEach(function(profile) {

                extraDetails += `
                    <div class="node-info-value">
                        • ${profile}
                    </div>
                `;
            });
        }

        if (
            data.condition &&
            data.type !== "role_mapping_condition" &&
            data.type !== "enforcement_condition"
        ) {

            extraDetails += `
                <div class="node-info-label">
                    Condition
                </div>

                <div class="node-info-value">
                    ${data.condition}
                </div>
            `;
        }

        if (data.profile_type) {

            extraDetails += `
                <div class="node-info-label">
                    Profile Type
                </div>

                <div class="node-info-value">
                    ${data.profile_type}
                </div>
            `;
        }


        if (
            data.type === "enforcement_profile" &&
            (
                data.policy_reference_count !== undefined ||
                data.service_reference_count !== undefined
            )
        ) {

            extraDetails += `
                <div class="node-info-label">
                    Usage Summary
                </div>

                <div class="node-info-value"
                    style="font-size:0.9rem;">
                    Other Policies:
                    ${data.policy_reference_count || 0}
                </div>

                <div class="node-info-value"
                    style="font-size:0.9rem;">
                    Other Services:
                    ${data.service_reference_count || 0}
                </div>
            `;
        }

        if (
            data.policy_references &&
            data.policy_references.length > 0
        ) {

            const externalRefs = [];

            data.policy_references.forEach(function(reference) {

                if (
                    reference.name !==
                    data.current_policy
                ) {

                    externalRefs.push(
                        reference
                    );
                }

            });
            

            if (externalRefs.length > 0) {

                extraDetails += `
                    <div class="node-info-label">
                        Referenced By Other Policies
                        (${externalRefs.length})
                    </div>
                `;

                externalRefs.forEach(function(ref) {

                    extraDetails += `
                        <div class="node-info-value"
                            style="
                                color:#FACC15;
                                font-size:0.9rem;
                                margin-top:6px;
                            ">
                            ${ref.name}
                        </div>
                    `;

                    if (
                        ref.services &&
                        ref.services.length > 0
                    ) {

                        ref.services.forEach(function(service) {

                            extraDetails += `
                                <div class="node-info-value"
                                    style="
                                        margin-left:15px;
                                        font-size:0.85rem;
                                    ">
                                    🔗<a href="/service/${service.id}"
                                        style="
                                            color:#FFFFFF;
                                            font-size: 0.9rem;
                                            text-decoration:underline;
                                        " 
                                       > ${service.name} </a>
                                </div>
                            `;

                        });

                    }

                });
                
            }
        }

        if (
            data.type === "enforcement_profile" &&
            data.service_references &&
            data.service_references.length > 0
        ) {

            extraDetails += `
                <div class="node-info-label">
                    Referenced By Other Services
                    (${data.service_references.length})
                </div>
            `;

            data.service_references.forEach(function(service) {

                extraDetails += `
                    <div class="node-info-value">
                        🔗<a href="/service/${service.id}"                       
                            style="
                                color:#FFFFFF;
                                font-size: 0.9rem;
                                text-decoration:underline;
                            "  
                        > ${service.name}</a>
                    </div>

                `;
            });
        }

        if (
            data.type === "role_mapping" &&
            data.service_references &&
            data.service_references.length > 0
        ) {

            extraDetails += `
                <div class="node-info-label"
                    style="font-size:0.9rem;">
                    Referenced By Other Services
                    (${data.service_references.length})
                </div>
            `;

            data.service_references.forEach(function(service) {
                extraDetails += `
                    <div class="node-info-value">
                        🔗<a href="/service/${service.id}"                       
                            style="
                                color:#FFFFFF;
                                font-size: 0.9rem;
                                text-decoration:underline;
                            "  
                        > ${service.name}</a>
                    </div>
                `;
            });
        }

        if (data.action) {

            extraDetails += `
                <div class="node-info-label">
                    Action
                </div>

                <div class="node-info-value">
                    ${data.action}
                </div>
            `;
        }

        if (data.attr_name) {

            extraDetails += `
                <div class="node-info-label">
                    Attribute Type
                </div>

                <div class="node-info-value">
                    ${data.attr_type || ""}
                </div>

                <div class="node-info-label">
                    Attribute Name
                </div>

                <div class="node-info-value">
                    ${data.attr_name}
                </div>

                <div class="node-info-label">
                    Attribute Value
                </div>

                <div class="node-info-value">
                    ${data.attr_value}
                </div>
            `;
        }


        if (
            data.attributes &&
            data.attributes.length > 0 &&
            data.type === "enforcement_profile"
        ) {

            extraDetails += `
                <div class="node-info-label">
                    Attributes
                </div>
            `;

            data.attributes.forEach(function(attr) {

                extraDetails += `
                    <div class="node-info-value">
                        <strong>${attr.name}</strong>
                        = ${attr.value || ""}
                        <br>
                        <span
                            style="
                                font-size:0.75rem;
                                color:#9CA3AF;
                            ">
                            ${attr.type || ""}
                        </span>
                    </div>
                `;
            });

        }

        infoPanel.innerHTML = `

            <div class="node-info-label">
                Name
            </div>

            <div class="node-info-value">
                ${data.label}
            </div>

            <div class="node-info-label">
                Type
            </div>

            <div class="node-info-value">
                <span class="status-ok">
                    ${nodeType}
                </span>
            </div>



            ${extraDetails}

        `;
    });

    let selectedNode = null;
    let layoutOptions;
    let searchMatches = [];
    let currentSearchIndex = -1;

    function focusSearchResult(index) {

        if (
            searchMatches.length === 0
        ) {
            return;
        }

        window.cy.nodes().removeClass(
            "active-search-match"
        );

        currentSearchIndex = index;

        const node =
            searchMatches[
                currentSearchIndex
            ];

        node.addClass(
            "active-search-match"
        );

        expandParents(
            node
        );

        window.cy.animate(
            {
                center: {
                    eles: node
                }
            },
            {
                duration: 300
            }
        );

        const resultCounter =
            document.getElementById(
                "searchResultCount"
            );

        if (
            resultCounter
        ) {

            resultCounter.textContent =
                `${currentSearchIndex + 1} of ${searchMatches.length}`;

        }

    }

    window.cy.on('mouseover', 'node', function(evt) {

        evt.target.connectedEdges().style({
            'line-color': '#FFFFFF',
            'target-arrow-color': '#FFFFFF',
            'width': 8
        });

    });

    window.cy.on('mouseout', 'node', function(evt) {

        evt.target.connectedEdges().style({
            'line-color': '#01A982',
            'target-arrow-color': '#01A982',
            'width': 5
        });

    });

    if (layoutName === "dagre") {
        layoutOptions = {
            name: "dagre",
            rankDir: "LR",
            nodeSep: 120,
            rankSep: 100,
            edgeSep: 60,
            padding: 40,
            fit: true
        };
    } else {
        layoutOptions = {
            name: "breadthfirst",
            directed: true,
            orientation: "horizontal",
            spacingFactor: 2.5,
            padding: 50,
            fit: true
        };
    }

    initialiseCollapsedBranches();

    const layout =
        window.cy.elements(":visible").layout(layoutOptions);

    layout.on("layoutstop", function () {

        window.cy.resize();

        window.cy.fit(
            window.cy.elements(":visible"),
            250
        );

    });

    layout.run();

const resetButton =
    document.getElementById("resetLayoutBtn");
if (resetButton) {
    resetButton.addEventListener(
        "click",
        function () {
            resetCollapsedBranches();
            selectedNode = null;

            const resetLayout =
                window.cy.elements(":visible").layout({
                    name: "dagre",
                    rankDir: "LR",
                    nodeSep: 120,
                    rankSep: 100,
                    edgeSep: 60,
                    padding: 40,
                    fit: true
                });

            resetLayout.run();
            setTimeout(() => {
                window.cy.fit(
                    window.cy.elements(":visible"),
                    60
                );
                window.cy.center();
            }, 300);
        }
    );

}


const fitButton =
    document.getElementById("fitGraphBtn");

if (fitButton) {

    fitButton.addEventListener(
        "click",
        function () {

            window.cy.fit(
                window.cy.elements(":visible"),
                60
            );

        }
    );

}

const centerButton =
    document.getElementById("centerGraphBtn");

if (centerButton) {

    centerButton.addEventListener(
        "click",
        function () {

            window.cy.center(
                window.cy.elements(":visible")
            );

        }
    );

}

function getExportFileName(format) {

    const serviceName =
        document.getElementById("serviceName")
            ?.textContent
            ?.trim()
            ?.replace(/[^a-zA-Z0-9_-]/g, "_")
        || "ClearPass_Policy";

    const date =
        new Date().toISOString().split("T")[0];

    return `${serviceName}_${date}.${format}`;
}


function exportGraph(format) {

    let imageData;

    if (format === "png") {

        imageData = window.cy.png({
            full: true,
            scale: 3,
            bg: "#ffffff"
        });

    } else if (format === "jpg") {

        imageData = window.cy.jpg({
            full: true,
            scale: 3,
            quality: 1.0,
            bg: "#ffffff"
        });

    } else {

        console.warn("Unsupported export format:", format);
        return;

    }

    const link =
        document.createElement("a");

    link.href =
        imageData;

    link.download =
        getExportFileName(format);

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}


const exportPngBtn =
    document.getElementById("exportPngBtn");

if (exportPngBtn) {

    exportPngBtn.addEventListener(
        "click",
        function (event) {

            event.preventDefault();

            exportGraph("png");

        }
    );

}


const exportJpgBtn =
    document.getElementById("exportJpgBtn");

if (exportJpgBtn) {

    exportJpgBtn.addEventListener(
        "click",
        function (event) {

            event.preventDefault();

            exportGraph("jpg");

        }
    );

}

const searchBox =
    document.getElementById(
        "graphSearch"
    );

if (searchBox) {

    searchBox.addEventListener(
        "input",
        function () {

            const searchText =
                this.value
                    .trim()
                    .toLowerCase();


            searchMatches = [];
            currentSearchIndex = -1;


            window.cy.elements().removeClass(
                "search-match active-search-match"
            );

            if (!searchText) {

                const resultCounter =
                    document.getElementById(
                        "searchResultCount"
                    );

                if (
                    resultCounter
                ) {
                    resultCounter.textContent = "";
                }

                return;
            }

            window.cy.nodes().forEach(
                function(node) {

                    const searchableText = [

                        node.data("label"),

                        node.data("role_name"),

                        node.data("default_role"),

                        node.data("default_profile"),

                        node.data("condition"),

                        node.data("attr_name"),

                        node.data("attr_value"),

                        node.data("action"),

                        node.data("profile_type"),

                        node.data("match_type")

                    ]
                    .filter(Boolean)
                    .join(" ")
                    .toLowerCase();

                    if (
                        searchableText.includes(
                            searchText
                        )
                    ) {

                        searchMatches.push(
                            node
                        );

                        expandParents(
                            node
                        );

                        node.addClass(
                            "search-match"
                        );

                        node.connectedEdges().addClass(
                            "search-match"
                        );

                    }

                }
            );

            const resultCounter =
                document.getElementById(
                    "searchResultCount"
                );

            if (
                searchMatches.length > 0
            ) {

                focusSearchResult(
                    0
                );

            } else {

                if (
                    resultCounter
                ) {
                    resultCounter.textContent =
                        "0 matches";
                }

            }
            

        }
    );

}

const clearSearchBtn =
    document.getElementById(
        "clearSearchBtn"
    );

if (
    clearSearchBtn
) {

    clearSearchBtn.addEventListener(
        "click",
        function () {

            searchBox.value = "";
            searchMatches = [];
            currentSearchIndex = -1;

            window.cy.elements().removeClass(
                "search-match active-search-match"
            );

            const resultCounter =
                document.getElementById(
                    "searchResultCount"
                );

            if (
                resultCounter
            ) {
                resultCounter.textContent = "";
            }

        }
    );

    const nextSearchBtn =
        document.getElementById(
            "nextSearchBtn"
        );

    if (
        nextSearchBtn
    ) {

        nextSearchBtn.addEventListener(
            "click",
            function () {

                if (
                    searchMatches.length === 0
                ) {
                    return;
                }

                let nextIndex =
                    currentSearchIndex + 1;

                if (
                    nextIndex >=
                    searchMatches.length
                ) {
                    nextIndex = 0;
                }

                focusSearchResult(
                    nextIndex
                );

            }
        );

    }

    const prevSearchBtn =
        document.getElementById(
            "prevSearchBtn"
        );

    if (
        prevSearchBtn
    ) {

        prevSearchBtn.addEventListener(
            "click",
            function () {

                if (
                    searchMatches.length === 0
                ) {
                    return;
                }

                let prevIndex =
                    currentSearchIndex - 1;

                if (
                    prevIndex < 0
                ) {
                    prevIndex =
                        searchMatches.length - 1;
                }

                focusSearchResult(
                    prevIndex
                );

            }
        );

    }

}
    
});