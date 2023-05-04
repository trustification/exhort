/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.redhat.ecosystemappeng.crda.integration.report;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.activation.DataHandler;
import javax.ws.rs.core.MediaType;

import org.apache.camel.Exchange;
import org.apache.camel.attachment.AttachmentMessage;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.traverse.BreadthFirstIterator;

import com.redhat.ecosystemappeng.crda.integration.GraphUtils;
import com.redhat.ecosystemappeng.crda.model.DependencyReport;
import com.redhat.ecosystemappeng.crda.model.GraphRequest;
import com.redhat.ecosystemappeng.crda.model.Issue;
import com.redhat.ecosystemappeng.crda.model.PackageRef;
import com.redhat.ecosystemappeng.crda.model.Recommendation;
import com.redhat.ecosystemappeng.crda.model.TransitiveDependencyReport;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class ReportTransformer {

    public List<DependencyReport> transform(GraphRequest request) {
        List<DependencyReport> result = new ArrayList<>();

        GraphUtils.getFirstLevel(request.graph()).forEach(d -> {
            Collection<Issue> issues = request.issues().get(d.name());
            if (issues == null) {
                issues = Collections.emptyList();
            }
            result.add(new DependencyReport(d, issues, getTransitiveDependenciesReport(d, request),
                    getRecommendations(issues, request.securityRecommendations()),
                    request.recommendations().get(d.toGav())));
        });
        return result.stream()
                .filter(r -> (r.issues() != null && !r.issues().isEmpty()) || !r.transitive().isEmpty()
                        || r.recommendation() != null)
                .collect(Collectors.toList());
    }

    private List<TransitiveDependencyReport> getTransitiveDependenciesReport(PackageRef start, GraphRequest request) {
        List<PackageRef> directDeps = GraphUtils.getNextLevel(request.graph(), start);
        BreadthFirstIterator<PackageRef, DefaultEdge> i = new BreadthFirstIterator<>(request.graph(), directDeps);
        List<TransitiveDependencyReport> result = new ArrayList<>();
        while (i.hasNext()) {
            PackageRef ref = i.next();
            Collection<Issue> issues = request.issues().get(ref.name());
            if (issues != null && !issues.isEmpty()) {
                result.add(
                        new TransitiveDependencyReport(ref, issues,
                                getRecommendations(issues, request.securityRecommendations())));
            }
        }
        return result;
    }
    
    public void attachHtmlReport(Exchange exchange) {
        exchange.getIn(AttachmentMessage.class).addAttachment("report.html",
                new DataHandler(exchange.getIn().getBody(String.class), MediaType.TEXT_HTML));

    }

    private Map<String, Recommendation> getRecommendations(Collection<Issue> issues,
            Map<String, Recommendation> recommendations) {
        Map<String, Recommendation> result = new HashMap<>();
        if (issues == null) {
            return result;
        }
        issues.stream().map(i -> i.cves()).flatMap(Set::stream).forEach(cve -> {
            Recommendation r = recommendations.get(cve);
            if (r != null) {
                result.put(cve, r);
            }
        });
        return result;
    }
}
